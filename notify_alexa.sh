#!/bin/bash
# SCRIPT GENERADO AUTOMÁTICAMENTE
read -r INPUT_JSON
LOGFILE="/var/ossec/logs/active-responses.log"
TOKEN="fd8f60f5f99625ed1454fbab96b1a1f2_786b3b68da7e7571e8f572223dae31dc"

# Extracción de datos
AGENT_ID=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.agent.id // "Unknown"')
IP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.srcip // "Unknown"')
AGENT_NAME=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.agent.name // "Unknown"')

# Lógica condicional
if [ "$AGENT_ID" == "002" ]; then
    FLOW="1002" # debian
    echo "$(date) | AR_EXEC | ID: $AGENT_ID ($AGENT_NAME) | IP: $IP | Flow: $FLOW" >> $LOGFILE
    curl -s "https://api-v2.voicemonkey.io/flows?token=${TOKEN}&flow=${FLOW}" > /dev/null 2>&1 &

elif [ "$AGENT_ID" == "003" ]; then
    FLOW="1000" # ubuntu
    echo "$(date) | AR_EXEC | ID: $AGENT_ID ($AGENT_NAME) | IP: $IP | Flow: $FLOW" >> $LOGFILE
    curl -s "https://api-v2.voicemonkey.io/flows?token=${TOKEN}&flow=${FLOW}" > /dev/null 2>&1 &

elif [ "$AGENT_ID" == "004" ]; then
    FLOW="1001" # debiantaul
    echo "$(date) | AR_EXEC | ID: $AGENT_ID ($AGENT_NAME) | IP: $IP | Flow: $FLOW" >> $LOGFILE
    curl -s "https://api-v2.voicemonkey.io/flows?token=${TOKEN}&flow=${FLOW}" > /dev/null 2>&1 &

else
    echo "$(date) | AR_IGNORED | ID: $AGENT_ID ($AGENT_NAME) | No coincide con reglas de notificación." >> $LOGFILE
fi
exit 0
