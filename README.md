# Iron-Scanner
```
[arhoc@ArchLinux Iron_Scanner ]$ perl Iron.pl -h

  _____ _____   ____  _   _                        
 |_   _|  __ \ / __ \| \ | |                       
   | | | |__) | |  | |  \| |                       
   | | |  _  /| |  | | . ` |                       
  _| |_| | \ \| |__| | |\  |                       
 |_____|_|__\_\____/|_| \_| _ _   _ ______ _____  
  / ____|/ ____|   /\   | \ | | \ | |  ____|  __ \ 
 | (___ | |       /  \  |  \| |  \| | |__  | |__) |
  \___ \| |      / /\ \ | . ` | . ` |  __| |  _  / 
  ____) | |____ / ____ \| |\  | |\  | |____| | \ \ 
 |_____/ \_____/_/    \_\_| \_|_| \_|______|_|  \_\
 
 
AVAILABLE SCAN TYPES:
  | -sS -> SYN PORT SCAN
  | -sT -> FULL CONNECT SCAN
  | -sA -> ACK PORT SCAN
  | -sW -> WINDOW PORT SCAN
  | -sM -> MAIMON PORT SCAN

CLI USAGE:
  | -p{port/range-ports} -> THE RANGE OF PORTS 2 SCAN, BY DEFAULT IT'S 1-65535
  | {Host or Services; IP Address or Range}
  ```
  
## Técnicas de Sondeo

- SYN Scan (-sS): Este tipo de escaneo envía paquetes TCP SYN al sistema objetivo sin completar el proceso de conexión, lo que puede permitir una evaluación rápida y eficiente del estado del puerto.

- Connect Scan (-sT): En este tipo de escaneo, se establece una conexión completa con cada puerto del sistema remoto para determinar si está abierto o cerrado. Es menos discreto que el escaneo SYN, ya que deja registros detallados de los intentos de conexión.

- ACK Scan (-sA): Este tipo de escaneo no busca determinar si los puertos están abiertos o cerrados, sino que busca determinar si existen firewalls o sistemas de seguridad en el camino y cómo están configurados.

- Window Scan (-sW): El escaneo de ventana es similar al escaneo SYN, pero envía paquetes TCP con valores de ventana inesperados para ver si el sistema responde de una manera determinada, lo que puede indicar la presencia de un firewall o sistema de seguridad.

- Maimon Scan (-sM): Este tipo de escaneo es similar al escaneo ACK, pero utiliza paquetes personalizados y específicos para ver cómo responde el sistema objetivo, lo que puede ayudar a identificar ciertos tipos de sistemas de seguridad o firewalls.

## Disclaimer
No me responsabilizo por cualquier uso poco ético o ilegal de este proyecto; fue escrito con meros propósitos educativos.
Sientete libre de contribuir a este proyecto o usarlo para tus proyectos! ^^
