# Tarea Corta 1 - ImageServer

Este proyecto implementa un demonio con el fin de brindar un servicio al usuario

## Compilar los programas

Primero asegurese de compilar los archivos antes de ejecutar 

```bash
gcc -o src/imageserver src/imageserver.c -lpthread -lm

gcc -o src/client src/client.c
```

## Ejecutar el servidor y el cliente

Para ejecutar el servidor y el cliente ejecute los siguientes comandos:

```bash
./src/imageserver.sh start

./src/client
```

## Cerrar cliente

Para cerrar el cliente solo digite el siguiente comando:

```bash
EXIT
```

## Detener servidor

Para detener el servidor solo digite el siguiente comando:

```bash
./src/imageserver.sh stop
```

## Otras acciones del servidos

Algunas de las otras acciones que puede hacer el servidor son las siguientes:

```bash
./src/imageserver.sh status     # Muestra el estado del servidor
```

```bash
./src/imageserver.sh restart    # Reinicia el servidor
```
