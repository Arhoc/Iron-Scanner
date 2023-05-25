#!/usr/bin/perl

use IO::Socket;
use Net::IP;
use Net::DNS;

# La dirección IP del host a escanear
my $host = "127.0.0.1";

# El rango de puertos a escanear
my $start_port = 1;
my $end_port = 65535;

# SYN PORT SCAN (sS)
sub syn_port_scan {
    my ($host, $port) = @_;
        my $socket = IO::Socket::INET->new(
            PeerAddr => $host,
            PeerPort => $port,
            Proto => 'tcp',
            Timeout => 1
        );

        # Si se pudo establecer una conexión, significa que el puerto está abierto
        if ($socket) {
            print "Puerto $port está abierto.\n";
            close($socket);
        }
}

# CONNECT() PORT SCAN (sT)
sub connect_port_scan {
    my ($host, $port) = @_;

    # Crear un socket TCP conectado al puerto especificado
    my $socket = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto => 'tcp',
        Timeout => 1
    );

    # Si se puede leer desde el socket, significa que el puerto está abierto
    if ($socket) {
        print "Puerto $port está abierto.\n";
        close($socket);
    }
}

# ACK PORT SCAN (sA)
sub ack_port_scan {
    my ($host, $port) = @_;

    # Crear un socket TCP sin conectarse
    my $socket = IO::Socket::INET->new(
        Proto => 'tcp',
        Timeout => 1
    );

    # Establecer el flag ACK en el paquete TCP
    my $ack_packet = pack('a4a4nnNNnna*',
                          "\x45",     # Versión y longitud de la cabecera IP
                          "\x00",     # Tipo de servicio
                          40,         # Longitud total del paquete (cabecera + datos)
                          0,          # Identificador
                          0b00000000, # Flags, Fragment Offset
                          64,         # TTL
                          IPPROTO_TCP,# Protocolo (TCP)
                          "\x00\x00", # Checksum (se calculará automáticamente)
                          "\x00\x00\x00\x00", # Direcciones IP origen y destino
                          0,          # Puerto origen
                          $port,      # Puerto destino
                          0x10,       # Flags TCP (ACK)
                          8192,       # Ventana TCP (mínima)
                          0           # Puntero urgente
                         );

    # Enviar el paquete ACK al puerto especificado
    if ($socket->connect($host, $port)) {

        # Si se recibe un paquete RST/ACK, significa que el puerto está filtrado
        print "Puerto $port está filtrado.\n";
        close($socket);
        return 1;
    } else {

        # Si se recibe un paquete ICMP, significa que el puerto está cerrado
        print "Puerto $port está cerrado.\n";
        close($socket);
        return 0;
    }
}

# WINDOW PORT SCAN (sW)
sub window_port_scan {
    my ($host, $port) = @_;

    # Crear un socket TCP sin conectarse
    my $socket = IO::Socket::INET->new(
        Proto => 'tcp',
        Timeout => 1
    );

    # Establecer la ventana TCP en el paquete
    my $window_packet = pack('a4a4nnNNnna*',
                             "\x45",     # Versión y longitud de la cabecera IP
                             "\x00",     # Tipo de servicio
                             40,         # Longitud total del paquete (cabecera + datos)
                             0,          # Identificador
                             0b00000000, # Flags, Fragment Offset
                             64,         # TTL
                             IPPROTO_TCP,# Protocolo (TCP)
                             "\x00\x00", # Checksum (se calculará automáticamente)
                             "\x00\x00\x00\x00", # Direcciones IP origen y destino
                             0,          # Puerto origen
                             $port,      # Puerto destino
                             0x02,       # Flags TCP (SYN)
                             8192,       # Ventana TCP (mínima)
                             0           # Puntero urgente
                            );

    # Enviar el paquete SYN-Window al puerto especificado
    if ($socket->connect($host, $port)) {

        # Si se recibe un paquete RST, significa que el puerto está cerrado
        print "Puerto $port está cerrado.\n";
        close($socket);
        return 0;
    } else {

        # Si se recibe un paquete SYN-ACK con una ventana cero, significa que el puerto está abierto
        my $response = "";
        $socket->recv($response, 1024);

        if ($response =~ /flags.*?sa/i && $response =~ /window.*?0/i) {
            print "Puerto $port está abierto.\n";
            close($socket);
            return 1;
        } else {
            close($socket);
            return 0;
        }
    }
}

# MAIMON PORT SCAN (sM)
sub maimon_port_scan {
    my ($host, $port) = @_;

    # Crear un socket TCP sin conectarse
    my $socket = IO::Socket::INET->new(
        Proto => 'tcp',
        Timeout => 1
    );

    # Establecer el flag PUSH en el paquete TCP
    my $push_packet = pack('a4a4nnNNnna*',
                           "\x45",     # Versión y longitud de la cabecera IP
                           "\x00",     # Tipo de servicio
                           40,         # Longitud total del paquete (cabecera + datos)
                           0,          # Identificador
                           0b00000000, # Flags, Fragment Offset
                           64,         # TTL
                           IPPROTO_TCP,# Protocolo (TCP)
                           "\x00\x00", # Checksum (se calculará automáticamente)
                           "\x00\x00\x00\x00", # Direcciones IP origen y destino
                           0,          # Puerto origen
                           $port,      # Puerto destino
                           0x08,       # Flags TCP (PUSH)
                           8192,       # Ventana TCP (mínima)
                           0           # Puntero urgente
                          );

    # Enviar el paquete PUSH al puerto especificado
    if ($socket->connect($host, $port)) {

        # Si se recibe una respuesta, significa que el puerto está abierto
        print "Puerto $port está abierto.\n";
        close($socket);
        return 1;
    } else {

        # Si no se recibe respuesta, significa que el puerto está cerrado o filtrado
        print "Puerto $port está cerrado o filtrado.\n";
        close($socket);
        return 0;
    }
}

sub find_hosts {
    my @direcciones = @_;

    my @hosts;

    foreach my $direccion (@direcciones) {
        # Si la dirección es una dirección IP individual
        if ($direccion =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
            push @hosts, $direccion;
        }

        # Si la dirección es un nombre DNS
        elsif ($direccion =~ /^[a-zA-Z0-9\.\-]+$/) {
            my $res = Net::DNS::Resolver->new();

            my $query = $res->search($direccion);
            if ($query) {
                foreach my $rr ($query->answer) {
                    next unless $rr->type eq "A";

                    push @hosts, $rr->address;
                }
            }
        }

        # Si la dirección es un rango de direcciones IP
        elsif ($direccion =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})\.(\d{1,3})-(\d{1,3})$/) {
            my $ip_base = $1;
            my $inicio_1 = $2;
            my $fin_1 = $3;
            my $inicio_2 = $4;
            my $fin_2 = $5;

            for (my $i = $inicio_1; $i <= $fin_1; $i++) {
                for (my $j = $inicio_2; $j <= $fin_2; $j++) {
                    push @hosts, "$ip_base$i.$j";
                }
            }
        }

        # Si la dirección es un rango CIDR
        elsif ($direccion =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/) {
            my $ip = Net::IP->new($direccion);

            while ($ip) {
                push @hosts, $ip->ip();
                $ip = $ip->next_ip();
            }
        }
    }

    return @hosts;
}

my @hosts = find_hosts(@ARGV);

foreach my $arg (@ARGV) {
    if ($arg eq "-h") {
        print q{
  _____ _____   ____  _   _                        
 |_   _|  __ \ / __ \| \ | |                       
   | | | |__) | |  | |  \| |                       
   | | |  _  /| |  | | . ` |                       
  _| |_| | \ \| |__| | |\  |                       
 |_____|_|__\_\\____/|_| \_| _ _   _ ______ _____  
  / ____|/ ____|   /\   | \ | | \ | |  ____|  __ \ 
 | (___ | |       /  \  |  \| |  \| | |__  | |__) |
  \___ \| |      / /\ \ | . ` | . ` |  __| |  _  / 
  ____) | |____ / ____ \| |\  | |\  | |____| | \ \ 
 |_____/ \_____/_/    \_\_| \_|_| \_|______|_|  \_\
 
 };

        print "\nAVAILABLE SCAN TYPES:\n";
        print "  | -sS -> SYN PORT SCAN\n";
        print "  | -sT -> FULL CONNECT SCAN\n";
        print "  | -sA -> ACK PORT SCAN\n";
        print "  | -sW -> WINDOW PORT SCAN\n";
        print "  | -sM -> MAIMON PORT SCAN\n\n";

        print "CLI USAGE:\n";
        print "  | -p{port/range-ports} -> THE RANGE OF PORTS 2 SCAN, BY DEFAULT IT'S 1-65535\n";
        print "  | {Host or Services; IP Address or Range}\n";
    }

    elsif ($arg =~ /^-p(.+)?$/) {
        # Se encontró un argumento que comienza con -p, obtener el valor del puerto o rango de puertos
        my $puerto = $1;
        
        if (!$puerto) {
            # Si no se proporcionó ningún valor después de -p, mostrar error y salir
            print "Error: debe especificar un puerto o rango de puertos después de la opción -p.\n";
            exit(1);
        } elsif ($puerto =~ /^(\d+)$/) {
            # Se especificó un solo puerto (Ejemplo: 80)
            my $puerto_num = int($puerto);

            # El rango de puertos a escanear es solo el puerto especificado
            $start_port = $puerto_num;
            $end_port = $puerto_num;
        } elsif ($puerto =~ /^(\d+)-(\d+)$/) {
            # Se especificó un rango de puertos
            my $inicio = $1;
            my $fin = $2;

            if ($inicio > $fin) {
                # Si el inicio del rango es mayor que el fin, intercambiarlos
                ($inicio, $fin) = ($fin, $inicio);
            }

            # Ahora tenemos el rango de puertos
            $start_port = $inicio;
            $end_port = $fin;
        } else {
            # El argumento siguiente no es válido
            print "Error: debe especificar un puerto o rango de puertos después de la opción -p.\n";
            exit(1);
        }
        
        last;
    }
    # Nótese que los argumentos no son robados de nmap

        elsif ($arg eq "-sS") {
            for (my $port = $start_port; $port <= $end_port; $port++) {
                syn_port_scan($host, $port);
            }
        }

        elsif ($arg eq "-sT") {
            for (my $port = $start_port; $port <= $end_port; $port++) {
                connect_port_scan($host, $port);
            }
        }

        elsif ($arg eq "-sA") {
            for (my $port = $start_port; $port <= $end_port; $port++) {
                ack_port_scan($host, $port);
            }
        }

        elsif ($arg eq "-sW") {
            for (my $port = $start_port; $port <= $end_port; $port++) {
                window_port_scan($host, $port);
            }
        }

        elsif ($arg eq "-sM") {
            for (my $port = $start_port; $port <= $end_port; $port++) {
                maimon_port_scan($host, $port);
            }
        }
    }