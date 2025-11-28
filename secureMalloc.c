#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// --- CONFIGURACIÓN DE SEGURIDAD ---
#define HEAP_SIZE 1024 * 10 // 10KB de memoria simulada
#define MAGIC_CANARY 0xDEADBEEF // Valor secreto para detectar corrupción

// Estructura de metadatos para cada bloque de memoria
typedef struct Block {
    size_t size;            // Tamaño del bloque (solicitado por el usuario)
    int is_free;            // 1 si está libre, 0 si está ocupado
    uint32_t canary_start;  // Canario al inicio (protección metadata)
    struct Block *next;     // Puntero al siguiente bloque
} Block;

// Memoria simulada (nuestro propio Heap)
uint8_t my_heap[HEAP_SIZE];
Block *free_list = (void*)my_heap;

// Inicializar el heap
void init_allocator() {
    free_list->size = HEAP_SIZE - sizeof(Block);
    free_list->is_free = 1;
    free_list->canary_start = MAGIC_CANARY;
    free_list->next = NULL;
    printf("[SECURE ALLOC] Heap initialized. Total size: %d bytes\n", HEAP_SIZE);
}

// --- MI VERSIÓN DE MALLOC ---
void *secure_malloc(size_t size) { //FUNC secure malloc
    Block *current = free_list;
    
    // Buscar un bloque libre (First-Fit Algorithm)
    while (current != NULL) {
        if (current->is_free && current->size >= size) {
            // Encontrado. Ahora lo dividimos (Split) si sobra espacio
            if (current->size > size + sizeof(Block)) {
                Block *new_block = (void*)((uint8_t*)current + sizeof(Block) + size);
                new_block->size = current->size - size - sizeof(Block);
                new_block->is_free = 1;
                new_block->canary_start = MAGIC_CANARY;
                new_block->next = current->next;
                
                current->size = size;
                current->next = new_block;
            }
            
            current->is_free = 0;
            current->canary_start = MAGIC_CANARY;
            
            // Escribir el "Canario de fin" justo después de los datos del usuario
            uint32_t *footer = (uint32_t*)((uint8_t*)current + sizeof(Block) + size);
            *footer = MAGIC_CANARY;
            
            // Devolvemos el puntero justo DESPUÉS de nuestros metadatos
            return (void*)((uint8_t*)current + sizeof(Block));
        }
        current = current->next;
    }
    return NULL; // Out of memory
}

// --- MI VERSIÓN DE FREE (CON DETECCIÓN DE HACKEO) ---
void secure_free(void *ptr) {
    if (!ptr) return;

    // Recuperar la estructura del bloque (retroceder el puntero)
    Block *block = (Block*)((uint8_t*)ptr - sizeof(Block));

    // 1. CHEQUEO DE SEGURIDAD: Metadata Corruption
    if (block->canary_start != MAGIC_CANARY) {
        printf("\n[!!!] CRITICAL SECURITY ALERT: Heap Metadata Corruption detected!\n");
        printf("[!!!] Possible Buffer Underflow attack. Aborting execution.\n");
        exit(1);
    }

    // 2. CHEQUEO DE SEGURIDAD: Buffer Overflow
    // Comprobar el canario al final del bloque
    uint32_t *footer = (uint32_t*)((uint8_t*)block + sizeof(Block) + block->size);
    if (*footer != MAGIC_CANARY) {
        printf("\n[!!!] CRITICAL SECURITY ALERT: Buffer Overflow detected!\n");
        printf("[!!!] The canary value was overwritten. Memory is compromised.\n");
        exit(1);
    }

    block->is_free = 1;
    printf("[SECURE ALLOC] Block freed successfully at %p\n", ptr);
}

// --- DEMOSTRACIÓN ---
int main() {
    init_allocator();

    printf("\n--- TEST 1: Normal Allocation ---\n");
    char *data = (char*)secure_malloc(16);
    strcpy(data, "Hello Security");
    printf("Allocated Data: %s\n", data);
    secure_free(data);

    printf("\n--- TEST 2: Simulating a Buffer Overflow Attack ---\n");
    // Pedimos 8 bytes
    char *vulnerable_buffer = (char*)secure_malloc(8);
    
    // ATACANTE: Escribe más de 8 bytes (12 bytes)
    // Esto sobrescribirá el "Canario" que pusimos al final
    printf("Writing 12 bytes into an 8-byte buffer...\n");
    // Usamos memcpy para forzar el desbordamiento (strcpy es peligroso)
    memcpy(vulnerable_buffer, "AAAAAAAABBBB", 12); 
    
    printf("Attempting to free memory...\n");
    // Al intentar liberar, nuestro sistema debería detectar el ataque
    secure_free(vulnerable_buffer);

    return 0;
}