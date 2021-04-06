#define BIMODAL_TABLE_SIZE 4096
#define TAGE_TABLE_SIZE 1024
#define MAX_COUNTER 3
#define MAX_COUNTER_TAGE 7
#define MAX_COUNTER_GLOBAL 15

#include <stdint.h>
#include <stdio.h>


struct table_entry {
    uint32_t u;
    uint32_t ctr;
    uint32_t tag;
};

int bimodal_table[BIMODAL_TABLE_SIZE];
table_entry T1[TAGE_TABLE_SIZE];
table_entry T2[TAGE_TABLE_SIZE];
table_entry T3[TAGE_TABLE_SIZE];
table_entry T4[TAGE_TABLE_SIZE];

uint32_t global_counter;
uint32_t shift_register;

extern "C" void initialize_branch_predictor()
{
    // Initializing all counters to 0.
    for (int i = 0; i < BIMODAL_TABLE_SIZE; i++) {
        bimodal_table[i] = 0;
    }

    // Intialization for table entries.
    for (int i = 0; i < TAGE_TABLE_SIZE; i++) {
        T1[i].u = 0;
        T1[i].ctr = 0;
        T1[i].tag = 0;

        T2[i].u = 0;
        T2[i].ctr = 0;
        T2[i].tag = 0;

        T3[i].u = 0;
        T3[i].ctr = 0;
        T3[i].tag = 0;

        T4[i].u = 0;
        T4[i].ctr = 0;
        T4[i].tag = 0;
    }

    global_counter = MAX_COUNTER_GLOBAL;
    shift_register = 0;
}

// A function to hash the tags for the tagged TAGE tables.
uint32_t hash_tag(unsigned long long ip, uint32_t hist_bits) {

    uint32_t XORed = ip ^ hist_bits;
    uint32_t XORed_0_7 = XORed % 256;
    uint32_t XORed_8_15 = (XORed / 256) % 256;
    uint32_t XORed_16_23 = ((XORed / 256) / 256) % 256;
    uint32_t XORed_24_31 = ((XORed / 256) / 256) / 256;
    return XORed_0_7 ^ XORed_8_15 ^ XORed_16_23 ^ XORed_24_31;

}

// A function to hash the index for the tagged TAGE tables.
uint32_t hash_index(unsigned long long ip, uint32_t hist_bits) {

    uint32_t XORed = ip ^ hist_bits;
    uint32_t XORed_0_9 = XORed % TAGE_TABLE_SIZE;
    uint32_t XORed_10_19 = (XORed / TAGE_TABLE_SIZE) % TAGE_TABLE_SIZE;
    uint32_t XORed_20_29 = ((XORed / TAGE_TABLE_SIZE) / TAGE_TABLE_SIZE) % TAGE_TABLE_SIZE;
    uint32_t XORed_30_31 = ((XORed / TAGE_TABLE_SIZE) / TAGE_TABLE_SIZE) / TAGE_TABLE_SIZE;
    return XORed_0_9 ^ XORed_10_19 ^ XORed_20_29 ^ XORed_30_31;

}

void predict_branch_helper(unsigned long long ip, unsigned long long hist, unsigned char *pred, unsigned char *normal, unsigned char *alternate, int *which_table_pred, int *which_table_alt)
{
    // Extracting bits from the PC.
    uint32_t hash = ip % BIMODAL_TABLE_SIZE;

    // Extracting bits from the history.
    uint32_t hist_0_1 = hist % 4;
    uint32_t hist_0_3 = hist % 16;
    uint32_t hist_0_7 = hist % 256;
    uint32_t hist_0_15 = hist % 65536;
    uint32_t hist_0_31 = hist;

    // Hashing the tags and indices.
    uint32_t T1_tag = hash_tag(ip, hist_0_3);
    uint32_t T1_index = hash_index(ip, hist_0_3);
    uint32_t T2_tag = hash_tag(ip, hist_0_7);
    uint32_t T2_index = hash_index(ip, hist_0_7);
    uint32_t T3_tag = hash_tag(ip, hist_0_15);
    uint32_t T3_index = hash_index(ip, hist_0_15);
    uint32_t T4_tag = hash_tag(ip, hist_0_31);
    uint32_t T4_index = hash_index(ip, hist_0_31);

    uint32_t computed_tags[4] = {T1_tag, T2_tag, T3_tag, T4_tag};
    table_entry entries[4] = {T1[T1_index], T2[T2_index], T3[T3_index], T4[T4_index]};

    // Obtaining the prediction from the bimodal table.
    unsigned char pred0 = (bimodal_table[hash] >= ((MAX_COUNTER + 1) / 2)) ? 1 : 0;

    // Determining the alternate prediction and the provider component prediction.
    unsigned char altpred;
    unsigned char provider_pred;
    unsigned char altpred_found = 0;
    unsigned char provider_pred_found = 0;
 
    for (int i = 3; i >= 0; i--) {
        table_entry entry = entries[i];
        
        if (entry.tag == computed_tags[i]) {
            provider_pred = (entry.ctr >= ((MAX_COUNTER_TAGE + 1) / 2)) ? 1 : 0;
            *which_table_pred = i;
            provider_pred_found = 1;
            
            // If we find a valid provider component prediction, we look for an alternate prediction.
            for (int j = i - 1; j >= 0; j--) {
                entry = entries[j];
                if (entry.tag == computed_tags[j]) {
                    altpred = (entry.ctr >= ((MAX_COUNTER_TAGE + 1) / 2)) ? 1 : 0;
                    *which_table_alt = j;
                    altpred_found = 1;
                    break;
                }
            }
            break;
        }
    }

    if (altpred_found == 0) {
        altpred = pred0;
        *which_table_alt = -1;
    }
    if (provider_pred_found == 0) {
        provider_pred = pred0;
        *which_table_pred = -1;
    }
    
    *alternate = altpred;
    *normal = provider_pred;    

    // Deciding between altpred and provider_pred for newly allocated entries.
    if (*which_table_pred != -1) {
        table_entry entry = entries[*which_table_pred];
        if ((entry.u == 0) && ((entry.ctr == 3) || (entry.ctr == 4))) {
            if (global_counter >= ((MAX_COUNTER_GLOBAL + 1) / 2)) {
                *pred = provider_pred;
            } else {
                *pred = altpred;
            } 
        } else {
            *pred = provider_pred;
        }
    } else {
        *pred = provider_pred;
    }
}

extern "C" void predict_branch(unsigned long long ip, unsigned long long hist, unsigned char *pred)
{
    int which_table_pred;
    int which_table_alt;
    unsigned char alternate;
    unsigned char normal;
    predict_branch_helper(ip, hist, pred, &normal, &alternate, &which_table_pred, &which_table_alt);   
}

extern "C" void update_branch(unsigned long long ip, unsigned long long hist, unsigned char taken)
{
    // Computing a "hash" from the PC.
    uint32_t hash = ip % BIMODAL_TABLE_SIZE;

    // Extracting bits from the history.
    uint32_t hist_0_1 = hist % 4;
    uint32_t hist_0_3 = hist % 16;
    uint32_t hist_0_7 = hist % 256;
    uint32_t hist_0_15 = hist % 65536;
    uint32_t hist_0_31 = hist;

    // Hashing the tags and indices.
    uint32_t T1_tag = hash_tag(ip, hist_0_3);
    uint32_t T1_index = hash_index(ip, hist_0_3);
    uint32_t T2_tag = hash_tag(ip, hist_0_7);
    uint32_t T2_index = hash_index(ip, hist_0_7);
    uint32_t T3_tag = hash_tag(ip, hist_0_15);
    uint32_t T3_index = hash_index(ip, hist_0_15);
    uint32_t T4_tag = hash_tag(ip, hist_0_31);
    uint32_t T4_index = hash_index(ip, hist_0_31);

    uint32_t computed_tags[4] = {T1_tag, T2_tag, T3_tag, T4_tag};
    table_entry *entries[4] = {&(T1[T1_index]), &(T2[T2_index]), &(T3[T3_index]), &(T4[T4_index])};

    // Obtaining the prediction information.
    int which_table_pred;
    int which_table_alt;
    unsigned char pred;
    unsigned char alternate;
    unsigned char normal;
    predict_branch_helper(ip, hist, &pred, &normal, &alternate, &which_table_pred, &which_table_alt);
 
    // Updating the useful counter.
    if (pred != alternate) {
        table_entry *entry = entries[which_table_pred];
        if ((pred == taken) && ((*entry).u < MAX_COUNTER)) {
            (*entry).u++;
        } else if ((pred != taken) && ((*entry).u > 0)) {
            (*entry).u--;
        }
    }

    // Updating the prediction counter.
    if (which_table_pred == -1) {
        if (taken && (bimodal_table[hash] < MAX_COUNTER)) {
            bimodal_table[hash]++;
        } else if ((taken == 0) && (bimodal_table[hash] > 0)) {
            bimodal_table[hash]--;   
        }   
    } else {
        table_entry *entry = entries[which_table_pred];
        if (taken && ((*entry).ctr < MAX_COUNTER_TAGE)) {
            (*entry).ctr++;
        } else if ((taken == 0) && ((*entry).ctr > 0)) {
            (*entry).ctr--;
        }
    }
    
    // Updating the tables when the overall prediction is incorrect and the provider component
    // does not use the most history bits.  
    if ((pred != taken) && (which_table_pred < 3)) {
        int allocation1 = -1;
        int allocation2 = -1;

        for (int i = which_table_pred + 1; i <= 3; i++) {
            table_entry *entry1 = entries[i];
            if ((*entry1).u == 0) {
                allocation1 = i;
                for (int j = i + 1; j <= 3; j++) {
                    table_entry *entry2 = entries[j];
                    if ((*entry2).u == 0) {
                        allocation2 = j;
                        break;
                    }
                }
                break;
            }
        }

        if (allocation1 != -1) {
            table_entry *entry;
            uint32_t allocation_tag;

            if (allocation2 != -1) {
                if (shift_register <= 1) {
                    // We allocate allocation1.
                    shift_register++;
                    entry = entries[allocation1];
                    allocation_tag = computed_tags[allocation1];
                } else {
                    // We allocate allocation2.
                    shift_register = 0;
                    entry = entries[allocation2];
                    allocation_tag = computed_tags[allocation2];
                }
            } else {
                // We allocate allocation1.
                entry = entries[allocation1];
                allocation_tag = computed_tags[allocation1]; 
            }
 
            (*entry).u = 0;
            (*entry).ctr = (taken == 1) ? 4 : 3;
            (*entry).tag = allocation_tag;           

        } else {
            // We decrement all the useful counters in the tables w/ more history.
            for (int i = which_table_pred + 1; i <= 3; i++) {
                table_entry *entry = entries[i];
                if ((*entry).u > 0) {
                    (*entry).u--;
                }
            }
        }        
    }

    // Updating the global counter.
    if (which_table_pred != -1) {
        table_entry *entry = entries[which_table_pred];
        if ((normal == taken) && (global_counter < MAX_COUNTER_GLOBAL)) {
            global_counter++;
        }  
        if ((alternate == taken) && (global_counter > 0)) {
            global_counter--;
        }
        // printf("GLOBAL COUNTER: %u\n", global_counter);
        // printf("NORMAL:         %u\n", normal);
        // printf("ALTERNATE:      %u\n", alternate);
        // printf("TAKEN:          %u\n\n", taken);
    }
}
















