#include <string.h>
#include <stdlib.h>
#include "http_requester.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_http_client.h"

char* buildUrl(char* baseUrl, char* uri)
{
	char * url = (char *) malloc(1 + strlen(baseUrl)+ strlen(uri) );
	strcpy(url, baseUrl);
	strcat(url, uri);
	return url;
}

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	MemoryStruct *mem = (MemoryStruct *)userp;

	mem->memory = (char *)realloc(mem->memory, mem->size + realsize + 1);
	if(mem->memory == NULL) {
		/* out of memory! */
		HTTP_ERROR("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

/* ---------- 내부 콜백 ---------- */
static esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    MemoryStruct *chunk = (MemoryStruct *)evt->user_data;

    switch (evt->event_id) {
    case HTTP_EVENT_ON_DATA:
        if (evt->data_len > 0 && chunk) {
            size_t new_len = chunk->size + evt->data_len;
            char *tmp = realloc(chunk->memory, new_len + 1);  // '\0' 공간 확보
            if (!tmp) return ESP_FAIL;

            chunk->memory = tmp;
            memcpy(chunk->memory + chunk->size, evt->data, evt->data_len);
            chunk->size = new_len;
            chunk->memory[chunk->size] = '\0';  // 널 종료
        }
        break;

    default:
        break;
    }

    return ESP_OK;
}

/* ---------- libcurl 스타일 호환 함수 ---------- */
HTTP_CURL_STATUS requestHttp(char *postData,
                             long postLength,
                             char *url,
                             MemoryStruct **returnData,
                             int option) // option == 1 ⇒ DELETE
{
    HTTP_CURL_STATUS result = HTTP_CURL_FAILURE;
    *returnData = NULL;

    MemoryStruct *chunk = calloc(1, sizeof(MemoryStruct));
    if (!chunk) return HTTP_CURL_FAILURE;

    esp_http_client_config_t cfg = {
        .url           = url,
        .event_handler = _http_event_handler,
        .timeout_ms    = 120 * 1000,
        .user_data     = chunk,
        //.transport_type = HTTP_TRANSPORT_OVER_TLS,
    };

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        ESP_LOGE("HTTP", "Failed to init client");
        free(chunk);
        return HTTP_CURL_FAILURE;
    }

    // HTTP Method 설정
    if (option) {
        esp_http_client_set_method(client, HTTP_METHOD_DELETE);
    } else if (postData) {
        esp_http_client_set_method(client, HTTP_METHOD_POST);
        esp_http_client_set_post_field(client, postData, postLength);
    } else {
        esp_http_client_set_method(client, HTTP_METHOD_GET);
    }

    // 공통 헤더 설정
    esp_http_client_set_header(client, "Accept", "application/json");
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "charsets", "utf-8");

    // 요청 전송
    esp_err_t err = esp_http_client_perform(client);
    int http_code = esp_http_client_get_status_code(client);

    if (err == ESP_OK && http_code == 200) {
        ESP_LOGI("HTTP", "HTTP OK, len=%zu", chunk->size);
        *returnData = chunk;
        result = HTTP_CURL_OK;
    } else {
        ESP_LOGE("HTTP", "Request failed, code=%d err=%s",
                 http_code, esp_err_to_name(err));
        *returnData = chunk; // 실패해도 chunk 안에 뭔가 있을 수 있으니 반환
        result = HTTP_CURL_FAILURE;
    }

    esp_http_client_cleanup(client);
    return result;
}

// HTTP_CURL_STATUS requestHttp(char *postData, long postLength, char* url, MemoryStruct** returnData, int option)
// {
// 	CURL *curl;
// 	CURLcode res;
// 	struct curl_slist *headers = NULL;

// 	headers = curl_slist_append(headers, "Accept: application/json");
// 	headers = curl_slist_append(headers, "Content-Type: application/json");
// 	headers = curl_slist_append(headers, "charsets: utf-8");

// 	curl = curl_easy_init();
// 	if(curl)
// 	{
// 		HTTP_INFO("\ncalling url = %s", url);
// 		if(option){
// 			curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
// 		}
// 		curl_easy_setopt(curl, CURLOPT_URL, url);
// 		if(postData!=NULL){
// 			HTTP_INFO("\nPost data = %s", postData);
// 			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData);
// 			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, postLength);
// 		}

// 		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

// 		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);

// 		MemoryStruct* chunk = (MemoryStruct*)malloc(sizeof(MemoryStruct));

// 		chunk->memory = (char *)malloc(1);  /* will be grown as needed by the realloc above */
// 		chunk->size = 0;    /* no data at this point */

// 		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

// 		/* we pass our 'chunk' struct to the callback function */
// 		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)chunk);

// 		/* Perform the request, res will get the return code */
// 		res = curl_easy_perform(curl);

// 		int http_code = 0;
// 		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

// 		if(http_code == HTTP_SUCCESS && res != CURLE_ABORTED_BY_CALLBACK)
// 		{
// 			HTTP_INFO("\nHTTP OK");
// 			HTTP_INFO("\nResponse = %s", chunk->memory);
// 			*returnData = chunk;
// 			curl_easy_cleanup(curl);
// 			return HTTP_CURL_OK;
// 		}
// 		else
// 		{
// 			HTTP_ERROR("curl_easy_perform() failed with httpcode = %d  and error = %s", http_code, curl_easy_strerror(res));
// 			*returnData = chunk;
// 			curl_easy_cleanup(curl);
// 			return HTTP_CURL_FAILURE;
// 		}
// 	}
// 	else
// 	{
// 		return HTTP_CURL_FAILURE;
// 	}
// }

