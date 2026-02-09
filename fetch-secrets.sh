#!/usr/bin/env bash

name=pensjon-psak-proxy-q2
namespace=pensjon-q2
cluster=dev-gcp
remote=http://localhost:9080
#remote=http://pensjon-psak-q2.ansatt.dev.nav.no

envfile=.env

bold=$(tput bold)
normal=$(tput sgr0)
white="[97;1m"
endcolor="[0m"

if command -v nais >& /dev/null; then
  DISCONNECT_STATUS=$(nais device status | grep -c Disconnected)

  if [ $DISCONNECT_STATUS -eq 1 ]; then
    read -p "Du er ikke koblet til med naisdevice. Vil du koble til? (j/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[YyjJ]$ ]]; then
      nais device connect
    else
      echo -e "${red}Du må være koblet til med naisdevice, avslutter${endcolor}"
      exit 1
    fi
  fi
fi

set -e
set -o pipefail

function fetch_kubernetes_secrets {
    local type=$1
    local context=$2
    local namespace=$3
    local secret=$4
    local mode=$5
    local A=("$@")

    echo -n -e "\t- $type "

    local context_namespace_secrets_value=$(kubectl --context="$context" -n "$namespace" get secrets)

    if [[ "mode" == "strict" ]]; then
        local secret_name=$(echo "$context_namespace_secrets_value" | awk "/$secret/ {print \$1}")
    else
        local secret_name=$(echo "$context_namespace_secrets_value" | grep "$secret" | tail -1 | awk '{print $1}')
    fi

    if [[ $secret_name == *$'\n'* ]]; then
       echo
       echo "Fant følgende hemmeligheter som samsvarte med søkestrengen \"$secret\". Støtter kun en hemmelighet"
       echo $secret_name
       exit 1
    fi

    local secret_response=$(kubectl --context="$context" -n "$namespace" get secret "$secret_name" -o json)

    for name in "${A[@]:5}"
    do
        {
          echo -n "$name='"
          echo "$secret_response" | jq -j ".data[\"$name\"]" | base64 --decode |  tr -d '\n'
          echo "'"
        } >> ${envfile}
    done

    echo -e "${bold}${white}✔${endcolor}${normal}"
}


rm -f "${envfile}"
touch "${envfile}"


echo -e "${bold}Henter secrets fra Kubernetes${normal}"

fetch_kubernetes_secrets "AzureAD" "${cluster}" "${namespace}" "${name}" "strict" \
    "AZURE_APP_CLIENT_ID" \
    "AZURE_APP_CLIENT_SECRET" \
    "AZURE_OPENID_CONFIG_ISSUER" \
    "AZURE_OPENID_CONFIG_JWKS_URI" \

echo

echo "REMOTE='${remote}'" >> "${envfile}"
echo "PENSJON-JIT-FOR-Q_URL='https://pensjon-jit-for-q.intern.dev.nav.no'" >> "${envfile}"
echo "PENSJON-JIT-FOR-Q_SCOPE='api://dev-gcp.pensjon-saksbehandling.pensjon-jit-for-q/.default'" >> "${envfile}"
echo "NAIS_TOKEN_EXCHANGE_ENDPOINT='http://127.0.0.1:7164/api/v1/token/exchange'" >> "${envfile}"

echo

echo "Hentet hemmeligheter og oppdatert filen ${bold}$(realpath ${envfile})${normal}"
