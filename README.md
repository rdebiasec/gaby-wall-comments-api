# gaby-wall-comments-api

Serverless API used by the Gabriella memorial wall to create and list guestbook entries stored in MongoDB.

## Environment variables

| Name | Description |
| --- | --- |
| `MONGODB_URI` | Connection string for the cluster (required). |
| `DB_NAME` | Database name, defaults to `Comments`. |
| `COLLECTION_NAME` | Collection used for wall entries, defaults to `Comments`. |
| `API_KEY` | Optional shared secret required via the `x-api-key` header. |
| `ALLOWED_ORIGINS` | Comma-separated list of origins that may call the API. Defaults to `*` so the form, smoke tests, and curl calls can run without CORS failures. |

## Notes

- The handler now responds to browser preflight requests (`OPTIONS`) with the necessary `Access-Control-Allow-*` headers. Requests that supply the API key continue to be required for `GET` and `POST`, but preflight checks no longer need the key.
- To troubleshoot future browser failures, inspect the Network tab for the `OPTIONS` request before the `POST`. A 204 status with the headers above means the issue is elsewhere (likely auth or validation).
