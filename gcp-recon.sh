#!/usr/bin/env bash
set -o pipefail

PROJECT_ID=""
BUCKET=""
WORDLIST=""
TIMEOUT=10

COLOR_RESET=""
COLOR_RED=""
COLOR_GREEN=""
COLOR_YELLOW=""
COLOR_BLUE=""
COLOR_CYAN=""
COLOR_MAGENTA=""

init_colors() {
  if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    COLOR_RESET=$'\033[0m'
    COLOR_RED=$'\033[31m'
    COLOR_GREEN=$'\033[32m'
    COLOR_YELLOW=$'\033[33m'
    COLOR_BLUE=$'\033[34m'
    COLOR_CYAN=$'\033[36m'
    COLOR_MAGENTA=$'\033[35m'
  fi
}

colorize_output() {
  local line=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      "[X]"*)
        printf '%b%s%b\n' "$COLOR_RED" "$line" "$COLOR_RESET"
        ;;
      "[OK]"*)
        printf '%b%s%b\n' "$COLOR_GREEN" "$line" "$COLOR_RESET"
        ;;
      "[!]"*)
        printf '%b%s%b\n' "$COLOR_YELLOW" "$line" "$COLOR_RESET"
        ;;
      "[*]"*|"[+]"*)
        printf '%b%s%b\n' "$COLOR_CYAN" "$line" "$COLOR_RESET"
        ;;
      "[?]"*)
        printf '%b%s%b\n' "$COLOR_MAGENTA" "$line" "$COLOR_RESET"
        ;;
      "===========================================")
        printf '%b%s%b\n' "$COLOR_BLUE" "$line" "$COLOR_RESET"
        ;;
      *)
        printf '%s\n' "$line"
        ;;
    esac
  done
}

REGIONS=(
  us-central1 us-east1 us-east4 us-west1
  northamerica-northeast1
  southamerica-east1
  europe-west1 europe-west2 europe-west3
)

COMMON_FUNCTIONS=(
  api app auth login register signup webhook
  upload download contracts contratos clientes users admin
  sendEmail notification notifications payment payments
)

COMMON_PATHS=(
  / /api /api/v1 /admin /login /debug /health /status
  /swagger.json /openapi.json /api-docs /docs
  /.env /config.js /firebase-config.js /main.js
)

banner() {
  echo
  echo "==========================================="
  echo "[!] $1"
  echo "==========================================="
}

usage() {
  echo "Usage: $0 <project-id> [-b|--bucket <bucket>] [-w|--wordlist <file>]"
  exit 1
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -b|--bucket)
        [[ -z "$2" ]] && usage
        BUCKET="$2"
        shift 2
        ;;
      -w|--wordlist)
        [[ -z "$2" ]] && usage
        WORDLIST="$2"
        shift 2
        ;;
      -h|--help)
        usage
        ;;
      -*)
        echo "[!] Unknown option: $1"
        usage
        ;;
      *)
        if [[ -z "$PROJECT_ID" ]]; then
          PROJECT_ID="$1"
          shift
        else
          echo "[!] Unexpected argument: $1"
          usage
        fi
        ;;
    esac
  done

  [[ -z "$PROJECT_ID" ]] && usage

  if [[ -z "$BUCKET" ]]; then
    BUCKET="$PROJECT_ID.firebasestorage.app"
  fi

  if [[ -n "$WORDLIST" && ! -f "$WORDLIST" ]]; then
    echo "[!] Wordlist file not found: $WORDLIST"
    exit 1
  fi
}

http_get() {
  curl -sS \
    --connect-timeout "$TIMEOUT" \
    --max-time "$TIMEOUT" \
    -w $'\n__HTTP_STATUS__:%{http_code}\n' \
    "$1"
}

http_post_json() {
  curl -sS \
    --connect-timeout "$TIMEOUT" \
    --max-time "$TIMEOUT" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$2" \
    -w $'\n__HTTP_STATUS__:%{http_code}\n' \
    "$1"
}

http_post_data() {
  curl -sS \
    --connect-timeout "$TIMEOUT" \
    --max-time "$TIMEOUT" \
    -X POST \
    -H "Content-Type: $3" \
    --data-binary "$2" \
    -w $'\n__HTTP_STATUS__:%{http_code}\n' \
    "$1"
}

http_patch_json() {
  curl -sS \
    --connect-timeout "$TIMEOUT" \
    --max-time "$TIMEOUT" \
    -X PATCH \
    -H "Content-Type: application/json" \
    -d "$2" \
    -w $'\n__HTTP_STATUS__:%{http_code}\n' \
    "$1"
}

http_delete() {
  curl -sS \
    --connect-timeout "$TIMEOUT" \
    --max-time "$TIMEOUT" \
    -X DELETE \
    -w $'\n__HTTP_STATUS__:%{http_code}\n' \
    "$1"
}

status_of() {
  grep "__HTTP_STATUS__:" | cut -d ":" -f2
}

body_of() {
  sed '/__HTTP_STATUS__:/d'
}

json_non_empty() {
  jq -e '
    if type == "object" then length > 0
    elif type == "array" then length > 0
    else . != null
    end
  ' >/dev/null 2>&1
}

print_collection_table_header() {
    printf '\n+-%-10s-+-%-30s-+-%-11s-+\n' "----------" "------------------------------" "-----------"
    printf '| %-10s | %-30s | %-11s |\n' "ACTION" "COLLECTION" "HTTP_STATUS"
    printf '+-%-10s-+-%-30s-+-%-11s-+\n' "----------" "------------------------------" "-----------"
}

print_collection_table_row() {
    local action="$1"
    local collection="$2"
    local status="$3"
    printf '| %-10s | %-30s | %-11s |\n' "$action" "$collection" "$status"
}

print_collection_table_footer() {
    printf '+-%-10s-+-%-30s-+-%-11s-+\n' "----------" "------------------------------" "-----------"
}

print_storage_table_header() {
    printf '\n+-%-10s-+-%-30s-+-%-11s-+\n' "----------" "------------------------------" "-----------"
    printf '| %-10s | %-30s | %-11s |\n' "ACTION" "BUCKET" "HTTP_STATUS"
    printf '+-%-10s-+-%-30s-+-%-11s-+\n' "----------" "------------------------------" "-----------"
}

print_storage_table_row() {
    local action="$1"
    local bucket="$2"
    local status="$3"
    printf '| %-10s | %-30s | %-11s |\n' "$action" "$bucket" "$status"
}

print_storage_table_footer() {
    printf '+-%-10s-+-%-30s-+-%-11s-+\n' "----------" "------------------------------" "-----------"
}

test_firestore_collection_crud() {
    local base="$1"
    local collection="$2"
    local response status body

    local test_doc_id="audit_$(date +%s)_$RANDOM"
    local test_doc_path="$base/$collection/$test_doc_id"
    local create_url="$base/$collection?documentId=$test_doc_id"

    local create_payload update_payload

    create_payload='{
      "fields": {
        "security_test": { "booleanValue": true },
        "operation": { "stringValue": "unauthenticated_create_test" },
        "created_by": { "stringValue": "firestore_rest_audit_script" }
      }
    }'

    update_payload='{
      "fields": {
        "security_test": { "booleanValue": true },
        "operation": { "stringValue": "unauthenticated_update_test" },
        "updated": { "booleanValue": true }
      }
    }'

    response="$(http_post_json "$create_url" "$create_payload")"
    status="$(echo "$response" | status_of)"
    print_collection_table_row "CREATE" "$collection" "$status"

    response="$(http_get "$test_doc_path")"
    status="$(echo "$response" | status_of)"
    print_collection_table_row "READ" "$collection" "$status"

    response="$(http_patch_json "$test_doc_path?updateMask.fieldPaths=operation&updateMask.fieldPaths=updated" "$update_payload")"
    status="$(echo "$response" | status_of)"
    print_collection_table_row "UPDATE" "$collection" "$status"

    response="$(http_delete "$test_doc_path")"
    status="$(echo "$response" | status_of)"
    print_collection_table_row "DELETE" "$collection" "$status"
}

check_firestore_api() {
    banner "Testing Firestore REST API"

    local base="https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents"
    local collections=()
    local found_collections=()

    echo "$base"

    echo "[*] Testing root endpoint..."

    local response status body

    response="$(http_get "$base")"
    status="$(echo "$response" | status_of)"
    body="$(echo "$response" | body_of)"

    if [[ "$status" == "200" ]] && echo "$body" | json_non_empty; then
        echo "[X] POSSIBLE EXPOSURE: Firestore root returned public data"
    elif [[ "$status" == "403" ]]; then
        echo "[OK] Firestore root blocked"
    else
        echo "[?] Firestore root HTTP $status"
    fi

    if [[ -n "$WORDLIST" ]]; then
        echo "[*] Bruteforcing collections from wordlist: $WORDLIST"

        while IFS= read -r line || [[ -n "$line" ]]; do
            collections+=("$line")
        done < <(sed '/^[[:space:]]*$/d; /^[[:space:]]*#/d' "$WORDLIST")

        if [[ "${#collections[@]}" -eq 0 ]]; then
            echo "[!] Wordlist is empty after filtering comments/blank lines"
        else
            print_collection_table_header
            for c in "${collections[@]}"; do
                response="$(http_get "$base/$c?pageSize=1")"
                status="$(echo "$response" | status_of)"
                body="$(echo "$response" | body_of)"
                print_collection_table_row "LIST" "$c" "$status"

                if [[ "$status" == "200" ]] && echo "$body" | jq -e '.documents | length > 0' >/dev/null 2>&1; then
                    found_collections+=("$c")
                elif [[ "$status" == "200" ]]; then
                    :
                fi

                test_firestore_collection_crud "$base" "$c"
            done
            print_collection_table_footer

            if [[ "${#found_collections[@]}" -gt 0 ]]; then
                :
            else
                :
            fi
        fi
    else
        echo "[*] Skipping Firestore collection bruteforce (no --wordlist provided)"
    fi

    echo "[*] Testing unauthenticated document creation/write/delete..."

    local test_collection="security_audit_tmp"
    local test_doc_id="audit_$(date +%s)_$RANDOM"
    local test_doc_path="$base/$test_collection/$test_doc_id"
    local create_url="$base/$test_collection?documentId=$test_doc_id"

    local create_payload update_payload

    create_payload='{
      "fields": {
        "security_test": { "booleanValue": true },
        "operation": { "stringValue": "unauthenticated_create_test" },
        "created_by": { "stringValue": "firestore_rest_audit_script" }
      }
    }'

    update_payload='{
      "fields": {
        "security_test": { "booleanValue": true },
        "operation": { "stringValue": "unauthenticated_update_test" },
        "updated": { "booleanValue": true }
      }
    }'

    echo "[*] Testing CREATE on $test_collection/$test_doc_id..."

    response="$(http_post_json "$create_url" "$create_payload")"
    status="$(echo "$response" | status_of)"
    body="$(echo "$response" | body_of)"

    if [[ "$status" == "200" ]]; then
        echo "[X] PUBLIC WRITE: unauthenticated document creation allowed"
    elif [[ "$status" == "403" ]]; then
        echo "[OK] Document creation blocked"
    else
        echo "[?] CREATE returned HTTP $status"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    fi

    echo "[*] Testing READ of created document..."

    response="$(http_get "$test_doc_path")"
    status="$(echo "$response" | status_of)"
    body="$(echo "$response" | body_of)"

    if [[ "$status" == "200" ]]; then
        echo "[X] PUBLIC READ: test document is readable"
    elif [[ "$status" == "403" ]]; then
        echo "[OK] Test document read blocked"
    elif [[ "$status" == "404" ]]; then
        echo "[OK] Test document does not exist / creation failed"
    else
        echo "[?] READ test document returned HTTP $status"
    fi

    echo "[*] Testing UPDATE/PATCH on test document..."

    response="$(http_patch_json "$test_doc_path?updateMask.fieldPaths=operation&updateMask.fieldPaths=updated" "$update_payload")"
    status="$(echo "$response" | status_of)"
    body="$(echo "$response" | body_of)"

    if [[ "$status" == "200" ]]; then
        echo "[X] PUBLIC WRITE: unauthenticated document update allowed"
    elif [[ "$status" == "403" ]]; then
        echo "[OK] Document update blocked"
    elif [[ "$status" == "404" ]]; then
        echo "[OK] Document update failed because document does not exist"
    else
        echo "[?] UPDATE returned HTTP $status"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    fi

    echo "[*] Testing DELETE on test document..."

    response="$(http_delete "$test_doc_path")"
    status="$(echo "$response" | status_of)"
    body="$(echo "$response" | body_of)"

    if [[ "$status" == "200" ]]; then
        echo "[X] PUBLIC DELETE: unauthenticated document deletion allowed"
    elif [[ "$status" == "403" ]]; then
        echo "[OK] Document deletion blocked"
    elif [[ "$status" == "404" ]]; then
        echo "[OK] Document deletion failed because document does not exist"
    else
        echo "[?] DELETE returned HTTP $status"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    fi
}

check_storage_api() {
    banner "Testing Cloud Storage / Firebase Storage"

    local bucket="$BUCKET"
    local firebase_base="https://firebasestorage.googleapis.com/v0/b/$bucket/o"
    local gcs_base="https://storage.googleapis.com/storage/v1/b/$bucket/o"
    local gcs_upload_base="https://storage.googleapis.com/upload/storage/v1/b/$bucket/o"
    local test_object="security_audit_tmp_$(date +%s)_$RANDOM.txt"
    local encoded_object
    local test_payload="storage_rest_audit_script"
    local response status

    encoded_object="$(jq -rn --arg v "$test_object" '$v|@uri')"

    response="$(http_get "$firebase_base?maxResults=5")"
    status="$(echo "$response" | status_of)"
    print_storage_table_header
    print_storage_table_row "LIST_FB" "$bucket" "$status"

    response="$(http_post_data "$firebase_base?name=$encoded_object" "$test_payload" "text/plain")"
    status="$(echo "$response" | status_of)"
    print_storage_table_row "WRITE_FB" "$bucket" "$status"

    response="$(http_get "$firebase_base/$encoded_object?alt=media")"
    status="$(echo "$response" | status_of)"
    print_storage_table_row "GET_FB" "$bucket" "$status"

    response="$(http_delete "$firebase_base/$encoded_object")"
    status="$(echo "$response" | status_of)"
    print_storage_table_row "DEL_FB" "$bucket" "$status"

    response="$(http_get "$gcs_base?maxResults=5")"
    status="$(echo "$response" | status_of)"
    print_storage_table_row "LIST_GCS" "$bucket" "$status"

    response="$(http_post_data "$gcs_upload_base?uploadType=media&name=$encoded_object" "$test_payload" "text/plain")"
    status="$(echo "$response" | status_of)"
    print_storage_table_row "WRITE_GCS" "$bucket" "$status"

    response="$(http_get "$gcs_base/$encoded_object?alt=media")"
    status="$(echo "$response" | status_of)"
    print_storage_table_row "GET_GCS" "$bucket" "$status"

    response="$(http_delete "$gcs_base/$encoded_object")"
    status="$(echo "$response" | status_of)"
    print_storage_table_row "DEL_GCS" "$bucket" "$status"
    print_storage_table_footer
}

check_realtime_db_api() {
    banner "Testing Firebase Realtime Database"

    local urls=(
        "https://$PROJECT_ID.firebaseio.com/.json"
        "https://$PROJECT_ID-default-rtdb.firebaseio.com/.json"
    )

    

    for url in "${urls[@]}"; do
        echo "[*] $url"

        local response status body
        response="$(http_get "$url")"
        status="$(echo "$response" | status_of)"
        body="$(echo "$response" | body_of)"

        if [[ "$status" == "200" ]]; then
        if echo "$body" | jq -e '.error == "Permission denied"' >/dev/null 2>&1; then
            echo "[OK] RTDB blocked"
        elif echo "$body" | jq -e '. != null and . != {}' >/dev/null 2>&1; then
            echo "[X] POSSIBLE EXPOSURE: RTDB returned public data"
            echo "$body" | jq 'if type=="object" then keys else . end'
        else
            echo "[?] RTDB returned empty/null"
        fi
        else
        echo "[?] HTTP $status"
        fi
    done
}

check_firebase_hosting() {
  banner "Testing Firebase Hosting"

  local hosts=(
    "https://$PROJECT_ID.web.app"
    "https://$PROJECT_ID.firebaseapp.com"
  )

  for host in "${hosts[@]}"; do
    echo "[*] Host: $host"

    for path in "${COMMON_PATHS[@]}"; do
      local response status body
      response="$(http_get "$host$path")"
      status="$(echo "$response" | status_of)"
      body="$(echo "$response" | body_of)"

      if [[ "$status" == "200" ]]; then
        case "$path" in
          /.env|/config.js|/firebase-config.js|/swagger.json|/openapi.json|/api-docs|/docs)
            echo "[X] INTERESTING PUBLIC PATH: $host$path"
            ;;
          *)
            echo "[+] Public path: $host$path"
            ;;
        esac

        if echo "$body" | grep -Eqi 'apiKey|projectId|storageBucket|databaseURL|private_key|client_email'; then
          echo "[X] Possible sensitive config found at: $host$path"
        fi
      fi
    done
  done
}

check_cloud_functions() {
  banner "Testing Cloud Functions"

  for region in "${REGIONS[@]}"; do
    for fn in "${COMMON_FUNCTIONS[@]}"; do
      local url="https://$region-$PROJECT_ID.cloudfunctions.net/$fn"
      local response status body

      response="$(http_get "$url")"
      status="$(echo "$response" | status_of)"
      body="$(echo "$response" | body_of)"

      if [[ "$status" =~ ^(200|201|204|301|302|400|401|403|405)$ ]]; then
        echo "[+] Function candidate: HTTP $status $url"

        if echo "$body" | grep -Eqi 'swagger|openapi|firebase|stack|trace|error|exception'; then
          echo "[!] Interesting response body at: $url"
        fi
      fi
    done
  done
}

check_cloud_run_guessing() {
  banner "Testing Cloud Run Known/Guessable Hosts"

  echo "[!] Cloud Run hostnames usually require service hash discovery."
  echo "[*] Checking only common custom subdomain patterns is not reliable."

  local candidates=(
    "https://api-$PROJECT_ID.a.run.app"
    "https://app-$PROJECT_ID.a.run.app"
    "https://$PROJECT_ID.a.run.app"
  )

  for url in "${candidates[@]}"; do
    local response status
    response="$(http_get "$url")"
    status="$(echo "$response" | status_of)"

    if [[ "$status" =~ ^(200|301|302|400|401|403|404|405)$ ]]; then
      echo "[+] Cloud Run candidate: HTTP $status $url"
    fi
  done
}

check_identity_toolkit() {
  banner "Testing Firebase Auth / Identity Toolkit"

  if [[ -z "$FIREBASE_API_KEY" ]]; then
    echo "[!] FIREBASE_API_KEY not set. Skipping active Auth API checks."
    echo "    Example:"
    echo "    FIREBASE_API_KEY='AIza...' $0 $PROJECT_ID"
    return
  fi

  echo "[*] Testing anonymous signup availability..."

  local url="https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$FIREBASE_API_KEY"
  local payload='{"returnSecureToken":true}'
  local response status body

  response="$(http_post_json "$url" "$payload")"
  status="$(echo "$response" | status_of)"
  body="$(echo "$response" | body_of)"

  if [[ "$status" == "200" ]] && echo "$body" | jq -e '.idToken' >/dev/null 2>&1; then
    echo "[X] Anonymous signup appears ENABLED"
  elif echo "$body" | grep -q "ADMIN_ONLY_OPERATION"; then
    echo "[OK] Anonymous signup blocked/admin-only"
  else
    echo "[?] Auth signup HTTP $status"
    echo "$body" | jq . 2>/dev/null || echo "$body"
  fi
}

check_remote_config() {
  banner "Testing Firebase Remote Config"

  if [[ -z "$FIREBASE_API_KEY" ]]; then
    echo "[!] FIREBASE_API_KEY not set. Skipping Remote Config check."
    return
  fi

  local app_id="${FIREBASE_APP_ID:-}"
  if [[ -z "$app_id" ]]; then
    echo "[!] FIREBASE_APP_ID not set. Remote Config usually needs appId."
    echo "    Example:"
    echo "    FIREBASE_API_KEY='AIza...' FIREBASE_APP_ID='1:123:web:abc' $0 $PROJECT_ID"
    return
  fi

  local url="https://firebaseremoteconfig.googleapis.com/v1/projects/$PROJECT_ID/namespaces/firebase:fetch?key=$FIREBASE_API_KEY"
  local payload
  payload="$(jq -n --arg appId "$app_id" '{"appId":$appId,"appInstanceId":"scanner","appInstanceIdToken":"scanner"}')"

  local response status body
  response="$(http_post_json "$url" "$payload")"
  status="$(echo "$response" | status_of)"
  body="$(echo "$response" | body_of)"

  if [[ "$status" == "200" ]] && echo "$body" | json_non_empty; then
    echo "[+] Remote Config returned data"
    echo "$body" | jq 'keys'
  else
    echo "[?] Remote Config HTTP $status"
    echo "$body" | jq . 2>/dev/null || echo "$body"
  fi
}

check_api_gateway_and_docs() {
  banner "Testing API Gateway / OpenAPI Discovery"

  local hosts=(
    "https://$PROJECT_ID.web.app"
    "https://$PROJECT_ID.firebaseapp.com"
  )

  local paths=(
    /swagger.json
    /openapi.json
    /api-docs
    /docs
    /v1/swagger.json
    /v1/openapi.json
  )

  for host in "${hosts[@]}"; do
    for path in "${paths[@]}"; do
      local response status body
      response="$(http_get "$host$path")"
      status="$(echo "$response" | status_of)"
      body="$(echo "$response" | body_of)"

      if [[ "$status" == "200" ]]; then
        echo "[X] Public API documentation candidate: $host$path"

        if echo "$body" | jq -e '.openapi or .swagger or .paths' >/dev/null 2>&1; then
          echo "[X] Valid OpenAPI/Swagger document found: $host$path"
        fi
      fi
    done
  done
}

main() {
  init_colors

  if [[ -n "$COLOR_RESET" ]]; then
    exec > >(colorize_output)
  fi

  parse_args "$@"

  command -v jq >/dev/null 2>&1 || {
    echo "[!] jq is required"
    exit 1
  }

  check_firestore_api
  check_storage_api
  check_realtime_db_api
  #check_firebase_hosting
  #check_cloud_functions
  check_cloud_run_guessing
  #check_identity_toolkit
  #check_remote_config
  #check_api_gateway_and_docs
}

main "$@"

