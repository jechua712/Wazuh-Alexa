#!/bin/bash

# ==============================================================================
# CONFIGURACIÓN Y RUTAS
# ==============================================================================
DB_FILE="/var/ossec/active-response/bin/alexa_endpoints.db"
SCRIPT_FILE="/var/ossec/active-response/bin/notify_alexa.sh"
XML_FILE="/var/ossec/etc/rules/local_rules.xml"
LOG_FILE="/var/ossec/logs/active-responses.log"
TOKEN="fd8f60f5f99625ed1454fbab96b1a1f2_786b3b68da7e7571e8f572223dae31dc"

# Colores para la terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ==============================================================================
# FUNCIONES GRÁFICAS Y UTILIDADES
# ==============================================================================

show_header() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
                _,.---.---.---.--.._ 
            _.-' `--.`---.`---'-. _,`--.._
           /`--._ .'.      `.      `,`-.`-._\
          ||    \  `.`---.__`__..-`. ,'`-._/
    _  ,`\ `-._\   \     `.     `_.-`-._,``-.
 ,`   `-_ \/ `-.`--.\     _\_.-'\__.-`-.`-._`.
(_.o> ,--. `._/'--.-`,--`   \_.-'        \`-._ \
 `---'    `._ `---._/__,----`            `-. `-\
           /_, ,  _..-'                    `-._\
           \_, \/ ._(
            \_, \/ ._\
             `._,\/ ._\
                `._// ./`-._
         JMC       `-._-_-_.-'
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}   WAZUH ALEXA AUTOMATION MANAGER v1.0${NC}"
    echo "==================================================="
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Por favor, ejecuta este script como root.${NC}"
        exit 1
    fi
}

# Inicializa la DB si no existe
init_db() {
    if [ ! -f "$DB_FILE" ]; then
        touch "$DB_FILE"
        echo -e "${GREEN}Base de datos creada en $DB_FILE${NC}"
    fi
}

# ==============================================================================
# LÓGICA DE GENERACIÓN DE ARCHIVOS
# ==============================================================================

apply_changes() {
    echo -e "\n${YELLOW}[*] Aplicando cambios...${NC}"

    # 1. GENERAR EL SCRIPT notify_alexa.sh
    # ------------------------------------
    echo "Generando script Bash..."
    
    cat <<EOF > "$SCRIPT_FILE"
#!/bin/bash

# SCRIPT GENERADO AUTOMÁTICAMENTE POR WAZUH ALEXA MANAGER
# NO EDITAR MANUALMENTE - USAR EL MANAGER

read -r INPUT_JSON

LOGFILE="$LOG_FILE"
TOKEN="$TOKEN"

# Extracción de datos
AGENT_ID=\$(echo "\$INPUT_JSON" | jq -r '.parameters.alert.agent.id // "Unknown"')
IP=\$(echo "\$INPUT_JSON" | jq -r '.parameters.alert.data.srcip // "Unknown"')
AGENT_NAME=\$(echo "\$INPUT_JSON" | jq -r '.parameters.alert.agent.name // "Unknown"')

# Lógica condicional generada
EOF

    # Bucle para leer la DB y crear los IF/ELIF
    first=true
    while IFS=":" read -r id name flow; do
        if [ "$first" = true ]; then
            echo "if [ \"\$AGENT_ID\" == \"$id\" ]; then" >> "$SCRIPT_FILE"
            first=false
        else
            echo "elif [ \"\$AGENT_ID\" == \"$id\" ]; then" >> "$SCRIPT_FILE"
        fi
        
        cat <<EOF >> "$SCRIPT_FILE"
    FLOW="$flow" # $name
    echo "\$(date) | AR_EXEC | ID: \$AGENT_ID (\$AGENT_NAME) | IP: \$IP | Flow: \$FLOW" >> \$LOGFILE
    curl -s "https://api-v2.voicemonkey.io/flows?token=\${TOKEN}&flow=\${FLOW}" > /dev/null 2>&1 &

EOF
    done < "$DB_FILE"

    # Cierre del bloque IF
    if [ "$first" = false ]; then
        cat <<EOF >> "$SCRIPT_FILE"
else
    echo "\$(date) | AR_IGNORED | ID: \$AGENT_ID (\$AGENT_NAME) | No coincide con reglas de notificación." >> \$LOGFILE
fi
EOF
    else
        # Caso raro: DB vacía
        echo "echo \"\$(date) | No agents configured\" >> \$LOGFILE" >> "$SCRIPT_FILE"
    fi

    echo "exit 0" >> "$SCRIPT_FILE"

    # Permisos y propietario
    chmod 755 "$SCRIPT_FILE"
    chown root:wazuh "$SCRIPT_FILE"


    # 2. ACTUALIZAR local_rules.xml
    # -----------------------------
    echo "Actualizando regla XML..."

    # Construir el regex: ^nombre1$|^nombre2$
    REGEX_STRING=""
    while IFS=":" read -r id name flow; do
        if [ -z "$REGEX_STRING" ]; then
            REGEX_STRING="^${name}$"
        else
            REGEX_STRING="${REGEX_STRING}|^${name}$"
        fi
    done < "$DB_FILE"

    if [ -z "$REGEX_STRING" ]; then
        REGEX_STRING="^NONE$" # Fallback si no hay agentes
    fi

    # Usamos sed para buscar el bloque de la regla 100005 y reemplazar solo la línea hostname
    # Busca desde id="100005" hasta el cierre de regla, y reemplaza la etiqueta hostname
    sed -i '/id="100005"/,/\/rule/ s|<hostname>.*</hostname>|<hostname>'"$REGEX_STRING"'</hostname>|' "$XML_FILE"

    # 3. VERIFICAR Y REINICIAR
    # ------------------------
    echo "Verificando configuración de Wazuh..."
    /var/ossec/bin/wazuh-analysisd -t > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Configuración válida. Reiniciando Wazuh Manager...${NC}"
        systemctl restart wazuh-manager
        echo -e "${GREEN}¡Éxito! Cambios aplicados.${NC}"
    else
        echo -e "${RED}ERROR: La configuración XML generada no es válida. Revisa $XML_FILE${NC}"
        /var/ossec/bin/wazuh-analysisd -t
    fi
    read -p "Presiona Enter para continuar..."
}

# ==============================================================================
# OPERACIONES DEL MENÚ
# ==============================================================================

list_endpoints() {
    echo -e "${BLUE}--- Endpoints Configurados ---${NC}"
    printf "%-5s %-20s %-10s\n" "ID" "NOMBRE" "FLOW"
    echo "---------------------------------------"
    if [ -s "$DB_FILE" ]; then
        while IFS=":" read -r id name flow; do
            printf "%-5s %-20s %-10s\n" "$id" "$name" "$flow"
        done < "$DB_FILE"
    else
        echo "No hay endpoints configurados."
    fi
    echo "---------------------------------------"
}

add_endpoint() {
    echo -e "${GREEN}--- Agregar Nuevo Endpoint ---${NC}"
    read -p "ID del Agente (ej. 002): " new_id
    read -p "Nombre del Agente (ej. debian): " new_name
    read -p "Flow ID de Voice Monkey (ej. 1002): " new_flow

    if [[ -z "$new_id" || -z "$new_name" || -z "$new_flow" ]]; then
        echo -e "${RED}Error: Todos los campos son obligatorios.${NC}"
        return
    fi

    # Verificar si ya existe
    if grep -q "^$new_id:" "$DB_FILE"; then
        echo -e "${RED}Error: El ID $new_id ya existe.${NC}"
    else
        echo "$new_id:$new_name:$new_flow" >> "$DB_FILE"
        echo -e "${GREEN}Agregado correctamente.${NC}"
        apply_changes
    fi
}

remove_endpoint() {
    list_endpoints
    echo -e "${RED}--- Eliminar Endpoint ---${NC}"
    read -p "Ingresa el ID del agente a eliminar: " target_id

    if grep -q "^$target_id:" "$DB_FILE"; then
        # Crear archivo temporal sin la línea
        grep -v "^$target_id:" "$DB_FILE" > "${DB_FILE}.tmp" && mv "${DB_FILE}.tmp" "$DB_FILE"
        echo -e "${GREEN}Eliminado correctamente.${NC}"
        apply_changes
    else
        echo -e "${RED}Error: ID no encontrado.${NC}"
        read -p "Presiona Enter..."
    fi
}

modify_endpoint() {
    list_endpoints
    echo -e "${YELLOW}--- Modificar Endpoint ---${NC}"
    read -p "Ingresa el ID del agente a modificar: " target_id

    # Extraer valores actuales
    current_line=$(grep "^$target_id:" "$DB_FILE")
    
    if [ -n "$current_line" ]; then
        IFS=":" read -r curr_id curr_name curr_flow <<< "$current_line"
        
        echo "Deja en blanco para mantener el valor actual."
        read -p "Nuevo Nombre [$curr_name]: " new_name
        read -p "Nuevo Flow [$curr_flow]: " new_flow

        # Asignar valores (si están vacíos, usa los viejos)
        new_name=${new_name:-$curr_name}
        new_flow=${new_flow:-$curr_flow}

        # Eliminar viejo y agregar nuevo
        grep -v "^$target_id:" "$DB_FILE" > "${DB_FILE}.tmp" && mv "${DB_FILE}.tmp" "$DB_FILE"
        echo "$target_id:$new_name:$new_flow" >> "$DB_FILE"
        
        echo -e "${GREEN}Modificado correctamente.${NC}"
        apply_changes
    else
        echo -e "${RED}Error: ID no encontrado.${NC}"
        read -p "Presiona Enter..."
    fi
}

# ==============================================================================
# BUCLE PRINCIPAL
# ==============================================================================
check_root
init_db

while true; do
    show_header
    list_endpoints
    echo ""
    echo "1. Agregar Endpoint"
    echo "2. Quitar Endpoint"
    echo "3. Modificar Endpoint"
    echo "4. Salir"
    echo ""
    read -p "Selecciona una opción: " opcion

    case $opcion in
        1) add_endpoint ;;
        2) remove_endpoint ;;
        3) modify_endpoint ;;
        4) echo "¡Hasta luego!"; exit 0 ;;
        *) echo "Opción no válida."; read -p "Presiona Enter..." ;;
    esac
done
