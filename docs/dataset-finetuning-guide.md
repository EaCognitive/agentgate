# Dataset Export Guide (Current API)

## Status

This document supersedes the old fine-tuning export flow.

As of 2026-02-16, the server exposes **pytest export** for datasets:

- `POST /api/datasets/{dataset_id}/export/pytest`

The previous `export/finetune*` endpoints are not present in the current API.

## Supported Dataset Endpoints

- `GET /api/datasets`
- `POST /api/datasets`
- `GET /api/datasets/{dataset_id}`
- `PATCH /api/datasets/{dataset_id}`
- `DELETE /api/datasets/{dataset_id}`
- `GET /api/datasets/{dataset_id}/tests`
- `POST /api/datasets/{dataset_id}/tests`
- `POST /api/datasets/{dataset_id}/tests/from-trace`
- `POST /api/datasets/{dataset_id}/tests/bulk-from-traces`
- `GET /api/datasets/{dataset_id}/runs`
- `POST /api/datasets/{dataset_id}/runs`
- `GET /api/datasets/{dataset_id}/runs/{run_id}`
- `GET /api/datasets/{dataset_id}/runs/{run_id}/results`
- `POST /api/datasets/{dataset_id}/export/pytest`

## Pytest Export API

### Endpoint

```http
POST /api/datasets/{dataset_id}/export/pytest
Authorization: Bearer <access_token>
```

### Query Parameters

- `async_tests` (bool, default: `false`)
- `include_assertions` (bool, default: `true`)
- `include_comments` (bool, default: `true`)

### Behavior

- Exports only `active` test cases from the dataset.
- Returns plain-text Python source for a runnable pytest module.
- Returns `400` when no active test cases exist.

## End-to-End Example

### 1. Create a dataset

```bash
curl -X POST "http://localhost:8000/api/datasets" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "support-regression",
    "description": "Customer support regression tests",
    "tags": ["support", "regression"]
  }'
```

### 2. Add a test case

```bash
curl -X POST "http://localhost:8000/api/datasets/1/tests" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "dataset_id": 1,
    "name": "Summarize billing issue",
    "tool": "summarize_ticket",
    "inputs": {
      "text": "User charged twice for January invoice"
    },
    "expected_output": {
      "summary": "Duplicate charge detected for January invoice"
    },
    "assertions": [
      {
        "type": "contains",
        "expected": "Duplicate charge",
        "field": "summary"
      }
    ]
  }'
```

### 3. Export pytest module

```bash
curl -X POST "http://localhost:8000/api/datasets/1/export/pytest?include_assertions=true&include_comments=true" \
  -H "Authorization: Bearer $TOKEN" \
  -o test_support_regression.py
```

### 4. Run exported tests

```bash
pytest test_support_regression.py -q
```

## Useful Variants

### Async export

```bash
curl -X POST "http://localhost:8000/api/datasets/1/export/pytest?async_tests=true" \
  -H "Authorization: Bearer $TOKEN" \
  -o test_support_regression_async.py
```

### Minimal export (no assertions/comments)

```bash
curl -X POST "http://localhost:8000/api/datasets/1/export/pytest?include_assertions=false&include_comments=false" \
  -H "Authorization: Bearer $TOKEN" \
  -o test_support_smoke.py
```

## CI Integration

```bash
curl -X POST "http://localhost:8000/api/datasets/$DATASET_ID/export/pytest" \
  -H "Authorization: Bearer $TOKEN" \
  -o generated_dataset_tests.py

pytest generated_dataset_tests.py -q
```

## Troubleshooting

### `400 No active test cases in dataset`

At least one test case must have `status=active`.

### `401` or `403` on export

- Ensure the bearer token is valid.
- Ensure the caller has dataset permissions in RBAC policy.

### Exported test import errors

The exported module imports `ea_agentgate.Agent`. Ensure the package is installed in the test environment.

## Migration Note

If your scripts still call `export/finetune`, migrate them to one of these options:

1. API export: `POST /api/datasets/{dataset_id}/export/pytest`
2. Offline corpus flow: use `scripts/generate_security_dataset.py` and
   `scripts/import_huggingface_datasets.py` for dataset generation/augmentation.
