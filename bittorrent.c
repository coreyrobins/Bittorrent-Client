#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <assert.h>
#include <sys/select.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "bencode.h"
#include "sha1.h"
#include "list.h"
#include "bitset.h"

typedef struct peer_connection {
	unsigned char *ip;
	unsigned short port;
	int socket_num;
	char *bitset;
	int bitset_len;
	int am_choked;
	int am_interested;
	int peer_choked;
	int peer_interested;
	int handshake_received;
	int socket_connected;
	int handshake_sent;
  int interested_sent;
	unsigned char *incomplete_msg_data;
	int bytes_read;
	int total_bytes;
  int piece_request_sent;
	struct peer_connection *nextlist;
	struct peer_connection *prevlist;
  unsigned char *write_data;
  int data_length;
} peer_connection;

typedef struct block {
  int requested;
  int received;
  int beginning;
  int end;
  int length;
  unsigned char *data;
} block;

typedef struct piece {
  int block_size;
  int blocks_requested;
  int blocks_received;
  unsigned char *hash;
  int piece_number;
  int size;
  int complete;
  int whole_piece_requested;
  char *file_name;
  int num_blocks;
  block *blocks;
} piece;

DEFINE_LIST(list, peer_connection);
struct list *peer_conns;
DEFINE_LINK(list, peer_connection);
IMPLEMENT_LIST(list, peer_connection);

peer_connection *find_connection(int sockfd);

char hex[] = "0123456789abcdef";
char peer_id[20];
int total_pieces;
int piece_length;
unsigned char *my_bitfield;

char i2a(char code);

void process_data(peer_connection *conn, char *handshake, char *torrent_name, int piece_len, piece *piece_array);
void process_have(peer_connection *conn);
void process_bitfield(peer_connection *conn);
void process_other_message(peer_connection *conn, char *torrent_name, int piece_len, piece *piece_array);
void send_bitfield(peer_connection *conn);
void send_piece_request(peer_connection *conn, piece *piece_array);

void calculate_bitfield(int piece_len, benc_val_t info_dict, int total_size, char *torrent_name);
void initialize_pieces_array(int piece_size, int total_size, piece *piece_array);
void write_piece_to_file(int piece_index, char *torrent_name, int piece_len, piece *piece_array);

void send_have_messages(int piece_index);

void send_block(unsigned int piece_index, unsigned int block_offset, unsigned int block_length, peer_connection *conn, char *torrent_name,
  int piece_len, piece *piece_array);

char i2a(char code) {
  return hex[code & 15];
}

peer_connection *find_connection(int sockfd) {
	struct peer_connection *curr = Get_Front_Of_list(peer_conns);
	while (curr != NULL) {
		if (curr->socket_num == sockfd) {
			return curr;
		} else {
			curr = Get_Next_In_list(curr);
		}
	}
	return NULL;
}

void process_data(peer_connection *conn, char *handshake, char *torrent_name, int piece_len, piece *piece_array) {

	if (conn->incomplete_msg_data != NULL) {
		if (conn->handshake_received && conn->handshake_sent) {

			// if we've sent and received the handshake, then it's another type of message

      process_bitfield(conn);
      process_have(conn);

      int tmp = ((total_pieces + 7) / 8);

      int i;
      if (!(conn->interested_sent)) {
        for (i=0; i<tmp; i++) {
          if (Is_Bit_Set(conn->bitset, i) && !Is_Bit_Set(my_bitfield, i)) {
            // send interested message
            unsigned char *message = malloc(5);
            unsigned long interested = htonl(1);
            memcpy(message, (unsigned char *) &interested, 4);
            message[4] = 2;
            if (write(conn->socket_num, message, 5) == -1) { 
              perror("Write error");
              conn->socket_connected = 0;
            }
            conn->interested_sent = 1;
            break;

          }
        }
      }

      process_other_message(conn, torrent_name, piece_len, piece_array);

		} else if (!(conn->handshake_received)) {
			// If the handshake has NOT been received yet..

			if (((memcmp(&((conn->incomplete_msg_data)[1]), "BitTorrent protocol", 19) == 0) && 
					conn->total_bytes >= 48)) {

        if (conn->total_bytes >= 68) {
          conn->handshake_received = 1;
          conn->total_bytes -= 68;
          (conn->incomplete_msg_data) += 68;
        }

				if (!(conn->handshake_sent)) {

					// if we've not sent the handshake, then send it (server side)

          if (write(conn->socket_num, handshake, 68) == -1) { 
            perror("Write error"); 
          }

					conn->handshake_sent = 1;
				}

        send_bitfield(conn);

        process_bitfield(conn);
        process_have(conn);

			}
		} 
	}
}

void process_have(peer_connection *conn) {
  if (conn->incomplete_msg_data != NULL && conn->total_bytes >= 9) {

    /*unsigned char first_byte_tmp = *((unsigned char *)&(conn->incomplete_msg_data)[0]);
    unsigned char second_byte_tmp = *((unsigned char *)&(conn->incomplete_msg_data)[1]);
    unsigned char third_byte_tmp = *((unsigned char *)&(conn->incomplete_msg_data)[2]);
    unsigned char fourth_byte_tmp = *((unsigned char *)&(conn->incomplete_msg_data)[3]);

    unsigned int find_len_for_have = (unsigned int) (first_byte_tmp << 24) | (unsigned int) (second_byte_tmp << 16) | 
      (unsigned int) (third_byte_tmp << 8) | (unsigned int) (fourth_byte_tmp);*/

    unsigned int *hopefully = (unsigned int *) conn->incomplete_msg_data;
    unsigned int money = ntohl(*hopefully);

    while (money == 323119476 && conn->total_bytes >= 68) {
      conn->total_bytes -= 68;
      (conn->incomplete_msg_data) += 68;
      hopefully = (unsigned int *) conn->incomplete_msg_data;
      money = ntohl(*hopefully);
    }

    unsigned char id = *((unsigned char *)&(conn->incomplete_msg_data)[4]);

    while (money == 5 && id == 4 && conn->total_bytes >= 9) {
      // HAVE MESSAGE

      unsigned char first_byte = *((unsigned char *)&(conn->incomplete_msg_data)[5]);
      unsigned char second_byte = *((unsigned char *)&(conn->incomplete_msg_data)[6]);
      unsigned char third_byte = *((unsigned char *)&(conn->incomplete_msg_data)[7]);
      unsigned char fourth_byte = *((unsigned char *)&(conn->incomplete_msg_data)[8]);

      uint_t have = (unsigned int) (first_byte << 24) | (unsigned int) (second_byte << 16) | 
      (unsigned int) (third_byte << 8) | (unsigned int) (fourth_byte);

      Set_Bit(conn->bitset, have);

      conn->total_bytes -= 9;
      (conn->incomplete_msg_data) += 9;

      if (conn->total_bytes >= 9) {
        hopefully = (unsigned int *) conn->incomplete_msg_data;
        money = ntohl(*hopefully);
        id = *((unsigned char *)&(conn->incomplete_msg_data)[4]);
      }

    }
  }
}

void process_bitfield(peer_connection *conn) {
  if (conn->incomplete_msg_data != NULL && conn->total_bytes >= 6) {

    unsigned char first_byte_tmp = *((unsigned char *)&(conn->incomplete_msg_data)[0]);
    unsigned char second_byte_tmp = *((unsigned char *)&(conn->incomplete_msg_data)[1]);
    unsigned char third_byte_tmp = *((unsigned char *)&(conn->incomplete_msg_data)[2]);
    unsigned char fourth_byte_tmp = *((unsigned char *)&(conn->incomplete_msg_data)[3]);

    unsigned int check_len = (unsigned int) (first_byte_tmp << 24) | (unsigned int) (second_byte_tmp << 16) | 
      (unsigned int) (third_byte_tmp << 8) | (unsigned int) (fourth_byte_tmp);

    unsigned char id = *((unsigned char *)&(conn->incomplete_msg_data)[4]);

    if (id == 5 && conn->total_bytes >= check_len + 4) {
      // BITSET MESSAGE
      check_len--;

      memcpy((conn->bitset), conn->incomplete_msg_data + 5, check_len);

      conn->total_bytes -= check_len;
      conn->total_bytes -= 5;
      (conn->incomplete_msg_data) += check_len + 1 + 4;
    }
  }
}

void process_other_message(peer_connection *conn, char *torrent_name, int piece_len, piece *piece_array) {
  if (conn != NULL && conn->incomplete_msg_data != NULL && conn->total_bytes >= 4) {

    unsigned char first_byte_tmp = *((unsigned char *)&(conn->incomplete_msg_data)[0]);
    unsigned char second_byte_tmp = *((unsigned char *)&(conn->incomplete_msg_data)[1]);
    unsigned char third_byte_tmp = *((unsigned char *)&(conn->incomplete_msg_data)[2]);
    unsigned char fourth_byte_tmp = *((unsigned char *)&(conn->incomplete_msg_data)[3]);

    unsigned int check_len = (unsigned int) (first_byte_tmp << 24) | (unsigned int) (second_byte_tmp << 16) | 
      (unsigned int) (third_byte_tmp << 8) | (unsigned int) (fourth_byte_tmp);

    unsigned char id = '\0';

    id = *((unsigned char *)&(conn->incomplete_msg_data)[4]);

    if (check_len == 0) {
      conn->incomplete_msg_data += 4;
      conn->total_bytes -= 4;
    } else if (conn != NULL && id == 0 && conn->total_bytes >= 5 && check_len == 1) {
      // choke message
      conn->am_choked = 1;
      conn->incomplete_msg_data += 5;
      conn->total_bytes -= 5;
    } else if (conn != NULL && id == 1 && conn->total_bytes >= 5 && check_len == 1) {
      // unchoke message
      conn->am_choked = 0;
      conn->incomplete_msg_data += 5;
      conn->total_bytes -= 5;

      // upon receiving unchoke message, send first request message
      send_piece_request(conn, piece_array);

    } else if (conn != NULL && id == 2 && conn->total_bytes >= 5) {

      puts("GOT INTERESTED MESSAGE********************");
      // interested message
      conn->peer_interested = 1;

      // if peer interested, send them an unchoke message

      unsigned char *msg = malloc(5);
      memcpy(msg, conn->incomplete_msg_data, 4);
      msg[4] = 1;

      if (write(conn->socket_num, msg, 5) == -1) { 
        perror("Write error"); 
      }

      conn->peer_choked = 0;
      conn->incomplete_msg_data += 5;
      conn->total_bytes -= 5;
    } else if (conn != NULL && id == 3 && conn->total_bytes >= 5) {
      // peer not interested message
      conn->peer_interested = 0;
      conn->incomplete_msg_data += 5;
      conn->total_bytes -= 5;
    } else if (conn != NULL && id == 6 && conn->total_bytes >= 17 && check_len == 13) {
      puts("GOT REQUEST MESSAGE");
      // request message

      unsigned char first = *((unsigned char *)&(conn->incomplete_msg_data)[5]);
      unsigned char second = *((unsigned char *)&(conn->incomplete_msg_data)[6]);
      unsigned char third = *((unsigned char *)&(conn->incomplete_msg_data)[7]);
      unsigned char fourth = *((unsigned char *)&(conn->incomplete_msg_data)[8]);

      unsigned int piece_index = (unsigned int) (first << 24) | (unsigned int) (second << 16) | 
        (unsigned int) (third << 8) | (unsigned int) (fourth);

      first = *((unsigned char *)&(conn->incomplete_msg_data)[9]);
      second = *((unsigned char *)&(conn->incomplete_msg_data)[10]);
      third = *((unsigned char *)&(conn->incomplete_msg_data)[11]);
      fourth = *((unsigned char *)&(conn->incomplete_msg_data)[12]);

      unsigned int block_offset = (unsigned int) (first << 24) | (unsigned int) (second << 16) | 
        (unsigned int) (third << 8) | (unsigned int) (fourth);

      first = *((unsigned char *)&(conn->incomplete_msg_data)[13]);
      second = *((unsigned char *)&(conn->incomplete_msg_data)[14]);
      third = *((unsigned char *)&(conn->incomplete_msg_data)[15]);
      fourth = *((unsigned char *)&(conn->incomplete_msg_data)[16]);

      unsigned int block_length = (unsigned int) (first << 24) | (unsigned int) (second << 16) | 
        (unsigned int) (third << 8) | (unsigned int) (fourth);

      // check to see if I have this piece (using my bitfield)
      // if I have the piece, then send him the piece
      // otherwise, do nothing

      if (Is_Bit_Set(my_bitfield, piece_index)) {
        send_block(piece_index, block_offset, block_length, conn, torrent_name, piece_len, piece_array);
      }

      conn->incomplete_msg_data += 17;
      conn->total_bytes -= 17;

    } else if (conn != NULL && id == 7 && conn->total_bytes >= check_len) {
      // piece message

      check_len -= 9;

      unsigned char first = *((unsigned char *)&(conn->incomplete_msg_data)[5]);
      unsigned char second = *((unsigned char *)&(conn->incomplete_msg_data)[6]);
      unsigned char third = *((unsigned char *)&(conn->incomplete_msg_data)[7]);
      unsigned char fourth = *((unsigned char *)&(conn->incomplete_msg_data)[8]);

      unsigned int piece_index = (unsigned int) (first << 24) | (unsigned int) (second << 16) | 
        (unsigned int) (third << 8) | (unsigned int) (fourth);

      first = *((unsigned char *)&(conn->incomplete_msg_data)[9]);
      second = *((unsigned char *)&(conn->incomplete_msg_data)[10]);
      third = *((unsigned char *)&(conn->incomplete_msg_data)[11]);
      fourth = *((unsigned char *)&(conn->incomplete_msg_data)[12]);

      unsigned int block_offset = (unsigned int) (first << 24) | (unsigned int) (second << 16) | 
        (unsigned int) (third << 8) | (unsigned int) (fourth);

      unsigned long block_index = ceil(((double)block_offset)/((double)piece_array[piece_index].block_size));

      printf("PIECE INDEX: %u BLOCK INDEX: %lu\n", piece_index, block_index);

      if (check_len == piece_array[piece_index].blocks[block_index].length) {
        puts("CORRECT LENGTH FOR BLOCK");
      }

      (piece_array[piece_index].blocks_received)++;

      conn->piece_request_sent = 0;

      piece *my_piece = &(piece_array[piece_index]);
      block *my_block = NULL;

      if (my_piece != NULL) {
        if (my_piece->blocks != NULL) {
          my_block = &((my_piece->blocks)[block_index]);
        }
      }

      if (my_piece != NULL && my_piece->blocks != NULL && my_block != NULL && my_block->received == 0) {
        //printf("CHECK LEN FOR PIECE: %d\n", check_len);
        piece_array[piece_index].blocks[block_index].data = malloc(check_len);
        if (piece_array[piece_index].blocks[block_index].data == NULL) {
          puts("MALLOC FAILED**********************************");
        }
        memcpy(piece_array[piece_index].blocks[block_index].data, conn->incomplete_msg_data + 13, check_len);

        my_block->received = 1;
        //free(&(conn->incomplete_msg_data));
        //conn->incomplete_msg_data = NULL;
        //conn->total_bytes = 0;
      }

      if (piece_array[piece_index].blocks_requested >= piece_array[piece_index].num_blocks) {
        if (piece_array[piece_index].blocks_received >= piece_array[piece_index].num_blocks) {
          printf("GOT ALL BLOCKS FOR PIECE: %u\n", piece_index);
          write_piece_to_file(piece_index, torrent_name, piece_len, piece_array);
          send_have_messages(piece_index);
        }
      }

      check_len += 9;

      conn->incomplete_msg_data += 4 + check_len;
      conn->total_bytes -= (4 + check_len);

      if (!(conn->am_choked)) {
        send_piece_request(conn, piece_array);
      }

    }

  }
}

void calculate_bitfield(int piece_len, benc_val_t info_dict, int total_size, char *torrent_name) {

  printf("PIECE LEN: %d\n", piece_len);
  printf("TOTAL PIECES: %d\n", total_pieces);
  printf("TOTAL SIZE: %d\n", total_size);

  sha1_state_s pms;
  sha1_byte_t output[SHA1_OUTPUT_SIZE];
  int len;

  benc_val_t *pieces_dict = tr_bencDictFind(&info_dict, "pieces");
  unsigned char *hash_list = (unsigned char *) tr_bencSaveMalloc(pieces_dict, &len);

  int i, j;
  for (i=0; i<30; i++) {
    if (hash_list[0] != ':') {
      hash_list++;
      len--;
    } else if (hash_list[0] == ':') {
      hash_list++;
      len--;
      break;
    }
  }

  FILE *fp;
  fp = fopen(torrent_name, "rb");

  // no matter what, need to initialize bitfield to 0
  my_bitfield = Create_Bit_Set(total_pieces);

  if (fp == NULL) {
    puts("FILE NOT FOUND");

    FILE *fp_two;
    fp_two = fopen(torrent_name, "wb");

    /*unsigned char *byte = malloc(piece_len);
    memset(byte, '\0', piece_len);

    for (i=0; i<total_pieces; i++) {
      if ((i+1) == total_pieces) {
        int tmp = total_size - (i * piece_len);
        fwrite(byte, 1, tmp, fp_two);
      } else {
        fwrite(byte, 1, piece_len, fp_two);
      }
    }*/

    fseek(fp_two, (total_size - 1), SEEK_SET);
    fwrite(&"\0", 1, 1, fp_two);

    fclose(fp_two); 

  }

  if (fp != NULL) {
    // keep reading in pieces from the file
    int bytes_read;
    unsigned char *buf = malloc(piece_len);
    while ((bytes_read = fread(buf, 1, piece_len, fp)) > 0) {
      // MUST TAKE INTO ACCOUNT LAST PIECE!!! --> just use bytes_read instead of piece_len for SHA1
      sha1_init(&pms);
      sha1_update(&pms, (sha1_byte_t *) buf, bytes_read);
      sha1_finish(&pms, output);
      int found = 0;
      int piece_number=0;
      for (i=0; i<(len-20) && !found; i+=20, piece_number++) {
        for (j=0; j<20; j++) {
          if (output != NULL && hash_list != NULL && output[j] != hash_list[i+j]) {
            break;
          }
          if (j == 19) {
            found = 1;
            //printf("GOT BIT: %d\n", piece_number);
            Set_Bit(my_bitfield, piece_number);
          }
        }
      }
    }
    free(buf);
    buf = NULL;
    fclose(fp);
  }

  puts("MY BITFIELD: ");
  Print_Bit_Set(my_bitfield, total_pieces);
  printf("\n");

  //test_write();

}

void send_bitfield(peer_connection *conn) {

  int tmp = ((total_pieces+7) / 8);

  unsigned char *bitfield = malloc(tmp + 5);

  unsigned long len = htonl(tmp + 1);

  memcpy(bitfield, (unsigned char *) &len, 4);

  bitfield[4] = 5;

  memcpy(bitfield + 5, my_bitfield, tmp);

  /*printf("BITFIELD MESSAGE: ");
  for(int i=0; i<tmp + 5; i++) {
    printf("%02x", ((unsigned char *)bitfield)[i]);
  }
  printf("\n");*/

  if (write(conn->socket_num, bitfield, tmp + 5) == -1) { 
    perror("Write error");
    conn->socket_connected = 0;
  }

}

void send_piece_request(peer_connection *conn, piece *piece_array) {

  unsigned char *message = malloc(17);

  unsigned long len = htonl(13);
  memcpy(message, (unsigned char *) &len, 4);

  message[4] = 6;

  unsigned long index_no;
  unsigned long piece_index=0;
  int i;

  int first_bit_free = Find_First_Free_Bit(my_bitfield, total_pieces);

  if (first_bit_free == -1) {
    puts("GOT ALL PIECES --> RETURNED -1");
  }

  int index_set=0;

  if (Is_Bit_Set(conn->bitset, first_bit_free) && !(piece_array[first_bit_free].whole_piece_requested)) {
    // if he has this first free bit, then send him a request for that bit
    // no need to do for loop as below
    index_no = htonl(first_bit_free);
    piece_index = first_bit_free;
    index_set = 1;
  } else {
    for (i=0; i<total_pieces; i++) {
      if (Is_Bit_Set(conn->bitset, i) && !Is_Bit_Set(my_bitfield, i)
            && !(piece_array[i].whole_piece_requested)) {
        index_set = 1;
        index_no = htonl(i);
        piece_index = i;
        break;
      }
    }
  }



  if (index_set == 1) {
    puts("FOUND INDEX");
    printf("REQUESTING PIECE: %lu\n", piece_index);
  } else {
    puts("DID NOT FIND INDEX --> NOT SENDING PIECE REQUEST");
  }

  //puts("MY BITFIELD: ");
  //Print_Bit_Set(my_bitfield, total_pieces);
  //printf("\n");

  memcpy(message + 5, (unsigned char *) &index_no, 4);

  for (i=0; i<piece_array[piece_index].num_blocks && index_set; i++) {
    if (!piece_array[piece_index].blocks[i].requested) {
      int tmp = piece_array[piece_index].blocks[i].beginning;
      unsigned long begin = htonl(tmp);
      memcpy(message + 9, (unsigned char *) &begin, 4);

      tmp = piece_array[piece_index].blocks[i].length;
      unsigned long length = htonl(tmp);
      memcpy(message + 13, (unsigned char *) &length, 4);

      piece_array[piece_index].blocks[i].requested = 1;

      if ((i+1) == piece_array[piece_index].num_blocks) {
        piece_array[piece_index].whole_piece_requested = 1;
      }

      break;
    }
  }

  (piece_array[piece_index].blocks_requested)++;

  if (first_bit_free != -1 && index_set) {
    conn->piece_request_sent = 1;
    if (write(conn->socket_num, message, 17) == -1) { 
      perror("Write error");
      conn->socket_connected = 0;
    }
  }

}

void initialize_pieces_array(int piece_size, int total_size, piece *piece_array) {

  //piece_array = malloc(sizeof(piece) * total_pieces);

  int i, j;
  for (i=0; i<total_pieces; i++) {
    piece_array[i].block_size = pow(2, 14);
    piece_array[i].blocks_requested = 0;
    piece_array[i].blocks_received = 0;
    piece_array[i].hash = malloc(20);
    piece_array[i].piece_number = i;
    if (i == (total_pieces - 1)) {
      // size of piece is (potentially) different for last piece
      piece_array[i].size = total_size - ((total_pieces - 1) * piece_size);
    } else {
      piece_array[i].size = piece_size;
    }
    //printf("PIECE INDEX: %d PIECE SIZE: %d\n", i, piece_array[i].size);
    piece_array[i].complete = 0;
    piece_array[i].whole_piece_requested = 0;

    int count=0;
    for (j=0; j<piece_array[i].size; j+=piece_array[i].block_size) {
      count++;
    }
    piece_array[i].num_blocks = count;

    piece_array[i].blocks = malloc(sizeof(block) * (count+1));

    int piece_index; // block offset
    for (j=0, piece_index=0; j<count; j++, piece_index += piece_array[i].block_size) {
      piece_array[i].blocks[j].requested = 0;
      piece_array[i].blocks[j].received = 0;
      piece_array[i].blocks[j].beginning = piece_index;
      piece_array[i].blocks[j].data = NULL;
      if (piece_index + piece_array[i].block_size >= piece_array[i].size) {
        // last block
        piece_array[i].blocks[j].end = piece_array[i].size;
        piece_array[i].blocks[j].length = piece_array[i].size - piece_index;
      } else {
        piece_array[i].blocks[j].end = piece_index + piece_array[i].block_size;
        piece_array[i].blocks[j].length = piece_array[i].block_size;
      }
    }
  }

}

void write_piece_to_file(int piece_index, char *torrent_name, int piece_len, piece *piece_array) {

  Set_Bit(my_bitfield, piece_index);

  piece *curr = &(piece_array[piece_index]);

  puts("GOT CURR");

  FILE *fp;
  fp = fopen(torrent_name, "rb+");
  if (fp == NULL) {
    puts("FAILED FOPEN");
    perror("fopen");
  }

  puts("FILE OPEN!");

  int file_offset = (piece_index * piece_len);
  printf("FILE OFFSET: %d\n", file_offset);

  fseek(fp, file_offset, SEEK_SET);

  puts("STARTING TO WRITE BLOCKS TO FILE");

  int i;
  for (i=0; i<curr->num_blocks; i++) {
    if ((&(curr->blocks[i]) != NULL) && ((curr->blocks[i].data) != NULL) && (fp != NULL)) {
      int bytes_written = fwrite(curr->blocks[i].data, 1, curr->blocks[i].length, fp);
      if (bytes_written <= 0) {
        perror("fwrite error inside WRITE PIECE TO FILE**********");
        printf("ERROR WHILE WRITING BLOCK: %d\n", i);
      } else if (bytes_written != curr->blocks[i].length) {
        puts("NOT ALL WRITTEN!!!");
      }
    } else {
      puts("BLOCK NULL???????????");
    }
  }

  piece_array[piece_index].complete = 1;

  puts("WROTE ALL BLOCKS TO FILE");

  if (fflush(fp) != 0) {
    puts("ERROR IN FFLUSH");
  }

  int ret;

  if (fp != NULL) {
    puts("FP NOT NULL");
    ret = fclose(fp);
    if (ret != 0) {
      puts("ERROR ON FCLOSE");
      perror("fclose");
    } else if (ret == 0) {
      puts("FCLOSE SUCCESS");
    }
    fp = NULL;
  }

  puts("CLOSED");

}

void send_block(unsigned int piece_index, unsigned int block_offset, unsigned int block_length, peer_connection *conn, char *torrent_name,
  int piece_len, piece *piece_array) {

  printf("PIECE LEN IN SEND BLOCK: %d\n", piece_len);

  puts("SENDING BLOCK TO PEER.....");

  printf("PIECE INDEX: %d\n", piece_index);
  printf("BLOCK OFFSET: %d\n", block_offset);
  printf("BLOCK LENGTH: %d\n", block_length);

  FILE *fp;
  fp = fopen(torrent_name, "rb+");

  int msg_len = (4+1+4+4+block_length);

  if (fp != NULL) {

    int opts = fcntl(conn->socket_num, F_GETFL);
    opts |= O_NONBLOCK;
    fcntl(conn->socket_num, F_SETFL, opts);
    
    unsigned char *buf = malloc(block_length);

    unsigned long file_offset = (piece_index * piece_len) + block_offset;

    fseek(fp, file_offset, SEEK_SET);

    int rd = fread(buf, 1, block_length, fp);

    if (rd == 0) {
      if (ferror(fp)) {
        perror("fread");
      }
    }

    unsigned char *msg = malloc(msg_len);

    int tmp_len = block_length + 9;

    unsigned long len = htonl(tmp_len);
    memcpy(msg, &len, 4);
    msg[4] = 7;

    unsigned long idx = htonl(piece_index);
    memcpy(msg + 5, &idx, 4);

    unsigned long begin = htonl(block_offset);
    memcpy(msg + 9, &begin, 4);

    memcpy(msg + 13, buf, block_length);

    int ret = 0;

    ret = write(conn->socket_num, msg, msg_len);

    if (ret == -1) {
      perror("Write error");
      conn->socket_connected = 0;
    }

    if (ret < msg_len) {
      puts("DIDNT WRITE WHOLE THING!");
      conn->data_length = msg_len - ret;
      conn->write_data = malloc(conn->data_length);
      memcpy(conn->write_data, (msg + ret), conn->data_length);
    }

    printf("BYTES WRITTEN: %d\n", ret);

    puts("WROTE PIECE MESSAGE TO PEER FROM REQUEST");

  }

}

void send_have_messages(int piece_index) {

  unsigned char *msg = malloc(4 + 1 + 4);

  unsigned long len = htonl(5);
  memcpy(msg, &len, 4);

  msg[4] = 4;

  unsigned long index_no = htonl(piece_index);
  memcpy(msg + 5, &index_no, 4);

  peer_connection *conn = Get_Front_Of_list(peer_conns);

  while (conn != NULL) {

    if (conn->socket_connected && !(Is_Bit_Set(conn->bitset, piece_index))) {

      printf("SENDING HAVE MESSAGE FOR PIECE: %d\n", piece_index);

      if (write(conn->socket_num, msg, (4 + 1 + 4)) == -1) { 
        perror("Write error");
        conn->socket_connected = 0;
      }
    }

    conn = Get_Next_In_list(conn);
  }

}

int main(int argc, char *argv[]) {
  
  struct stat sb;
  struct addrinfo hints, *result, *p;
  char *torrent_file, *announce_str, *host, *port, *to_encode_str, *url_encode, tmp[15], *get_request, *path_final;
  char *peer_str, *buf, *length, *small_buf, *tmp_char;
  long left;
  int len, i, pid, sockfd=-1, bytes_read, total_bytes=0, counter=0;
  FILE *fp;
  benc_val_t values, *announce, *to_encode, *peers, values_two;
  sha1_state_s pms;
  sha1_byte_t output[SHA1_OUTPUT_SIZE];

  fd_set master, read_fds, write_fds, error_fds;
  int listener, new_fd=0;
  int fdmax;

  int piece_len;
  char *piece_len_tmp;
  int num_pieces;

  socklen_t addrlen;

  struct timeval start, current, remaining;

  struct sockaddr_storage remoteaddr;

  struct sockaddr_in bind_addr;
  unsigned int bind_addr_len;

  int exit_loop=0;

  struct sockaddr_in ip_addr;
  unsigned int ip_addr_len;
  unsigned char *ip;

  piece *piece_array;

  peer_conns = malloc(sizeof(struct list));
  Clear_list(peer_conns);

  if (argc != 2) {
    fprintf(stderr, "Invalid Arguments.\n");
  }

  /* call stat */
  if (stat(argv[1], &sb) == -1) {
    perror("stat");
  }

  /* allocate space for torrent_file to read in from the torrent itself */
  torrent_file = (char *) malloc(sb.st_size);

  /* error checking */
  if (torrent_file == 0) {
    perror("malloc");
  }

  /* open the torrent file for reading */
  fp = fopen(argv[1], "r");
  if (fp == NULL) {
    perror("fopen");
  }

  /* read in torrent file to torrent_file */
  if (fread(torrent_file, 1, sb.st_size, fp) == 0) {
    if (ferror(fp)) {
      perror("fread");
    }
  }

  /* encode it, and store output in values */
  if (_tr_bencLoad(torrent_file, sb.st_size, &values, NULL) == 1) {
    perror("_tr_bencLoad");
  }

  /* get the announce dict and string */
  announce = tr_bencDictFind(&values, "announce");
  announce_str = tr_bencStealStr(announce);

  host = malloc(100);
  port = malloc(100);
  path_final = malloc(100);

  sscanf (announce_str,"http://%[^:]:%[^/]/%s", host, port, path_final);
  if(strlen(port) == 0){
    sscanf (announce_str,"http://%[^/]/%s", host, path_final);
    strcpy(port, "80");
  }

  /* hash the info dictionary (to_encode) */
  to_encode = tr_bencDictFind(&values, "info");
  to_encode_str = tr_bencSaveMalloc(to_encode, &len);

  sha1_init(&pms);
  sha1_update(&pms, (sha1_byte_t *) to_encode_str, len);
  sha1_finish(&pms, output);

  /* get piece length */
  piece_len_tmp = strstr(to_encode_str, "piece lengthi");
	if (piece_len_tmp == NULL) {
		perror("length missing");
	}

	piece_len_tmp += 13;

	for (i=0; ; i++) {
    if (piece_len_tmp[i] == 'e') {
      piece_len_tmp[i] = '\0';
      break;
    }
  }

	piece_len = atoi(piece_len_tmp);

  /* get the length for left in the GET request */
  length = strstr(to_encode_str, "lengthi");
  length += 7;
  /*extra_length = strstr(length, "lengthi");*/

  for (i=0; i<strlen(length); i++) {
    if (length[i] == 'e') {
      length[i] = '\0';
      break;
    }
  }

  left=atoi(length);

  num_pieces = ceil(((double)left)/((double)piece_len));
  total_pieces = num_pieces;
  piece_length = piece_len;

  // get the file name for the bitfield
  benc_val_t *info_dict = tr_bencDictFind(&values, "info");

  //benc_val_t *name_dict = tr_bencDictFind(info_dict, "name");
  char *info_string = tr_bencSaveMalloc(info_dict, &len);
  char *torrent_name = strstr(info_string, "name");
  torrent_name += 4;
  
  int firstColonFound = 0;
  int secondColonFound = 0;
  for (i=0; i<strlen(torrent_name); i++) {
    if (torrent_name[i] == ':' && !firstColonFound) {
      torrent_name += i + 1;
      firstColonFound = 1;
    } else if (torrent_name[i] == ':' && !secondColonFound) {
      secondColonFound = 1;
      torrent_name[i-2] = '\0';
      torrent_name[i-1] = '\0';
      torrent_name[i] = '\0';
    } 
  }

  calculate_bitfield(piece_len, *info_dict, left, torrent_name);
  piece_array = malloc(sizeof(piece) * total_pieces);
  initialize_pieces_array(piece_len, left, piece_array);

  /* url encode the hash */
  buf = url_encode = (char *) malloc(20 * 3 + 1);
  for (i=0; i<20; i++) {
    if (isalnum(output[i]) || output[i] == '-' || output[i] == '_' || output[i] == '.' || output[i] == '~') {
      *buf++ = output[i];
    } else if (output[i] == ' ') {
      *buf++ = '+';
    } else {
      *buf++ = '%';
      *buf++ = i2a(output[i] >> 4); 
      *buf++ = i2a(output[i] & 15);
    }
  }
  *buf = '\0';  	

  /* construct peer_id */
  pid = getpid();

  strcpy(peer_id, "CS417037-");
  sprintf(tmp, "%d-", pid);
  strcat(peer_id, tmp);

  for (i=strlen(peer_id); i<20; i++) {
    peer_id[i]='c';
  }
  peer_id[i] = '\0';

  /* listen, bind, getsockname */
  if ((listener = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("socket");
  }

  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind_addr.sin_port = htons(0);
  bind_addr_len = sizeof(struct sockaddr);

  if ((bind(listener, (struct sockaddr *) &bind_addr, sizeof(bind_addr))) < 0)
  {
    perror("bind");
    close(listener);
  }

  if ((listen(listener, 5)) < 0)
  {
    perror("listen");
    close(listener);
  }

  getsockname(listener, (struct sockaddr *) &bind_addr, &bind_addr_len);

  fprintf(stderr, "listening on %s:%d\n", inet_ntoa(bind_addr.sin_addr), ntohs(bind_addr.sin_port));

  /* call gettimeofday() */
	gettimeofday(&start, NULL);

	/* construct GET request */
  int ret_val = asprintf(&get_request, "GET /%s?info_hash=%s&peer_id=%s&port=%d&uploaded=0&downloaded=0&left=%ld&compact=1&event=started HTTP/1.1\r\nHost:%s\r\n\r\n",
	   path_final, url_encode, peer_id, ntohs(bind_addr.sin_port), left, host);

  if (ret_val < 0) {
    perror("asprintf");
  }

  char *handshake = malloc(68);

	handshake[0]=19;
	memcpy((&handshake[1]), "BitTorrent protocol", 19);
	memset((&handshake[1+19]), '\0', 8);
	memcpy((&handshake[1+19+8]), &output, 20);
	memcpy((&handshake[1+19+8+20]), &peer_id, 20);

  /* connect with host */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(host, port, &hints, &result) != 0) { 
    fprintf(stderr, "Could not find hostname.\n"); 
  }
  for(p = result; p != NULL; p = p->ai_next) {
    sockfd = socket(p->ai_family, p->ai_socktype, 0);
    if (sockfd == -1) {
      continue; 
    }
    if (connect(sockfd, p->ai_addr, p->ai_addrlen) != -1) { 
      break; 
    }
    close(sockfd); 
  }
  if (p == NULL) {
    fprintf(stderr, "Could not connect\n"); 
  }

  /* write get_request to the socket */
  if (write(sockfd, get_request, strlen(get_request)) == -1) { 
    perror("Write error"); 
  }

  /* shutdown the socket for writing */
  if(shutdown(sockfd, SHUT_WR)) {
    perror("Error shutting down"); 
  }

  /* allocate space for the second buffer to keep ALL the data read from the socket */
  buf = NULL;
  buf = malloc(BUFSIZ);

  /* allocate space for small_buf to read in little by socket from the socket */
  small_buf = malloc(100);
  memset(small_buf, '\0', 100);

  /* read in from the socket to small_buf up to 100 chars, and copy those into buf_two */
  while (((bytes_read = read(sockfd, small_buf, 100)) > 0) && 
	 total_bytes < BUFSIZ) {
    memcpy(buf+total_bytes, small_buf, bytes_read);
    total_bytes += bytes_read;
    memset(small_buf, '\0', bytes_read);
  }

  /* find the first instance of \r\n\r\n and get rid of everything up to that point */
  for (tmp_char=buf; counter<total_bytes; tmp_char++, counter++) {
    if (strncmp(tmp_char, "\r\n\r\n", 4) == 0) {
      break;
    }
  }

  /* remove the \r\n\r\n from the string tmp_char */
  tmp_char+=4;

  /* parse the values */
  if (_tr_bencLoad(tmp_char, total_bytes - (tmp_char - buf), &values_two, NULL) == 1) {
    perror("_tr_bencLoad");
  }

  /* get the peers dictionary */
  if ((peers = tr_bencDictFind(&values_two, "peers")) == NULL) {
    perror("no peers");
  }

  peer_str = peers->val.s.s;

  FD_ZERO(&master);
	FD_ZERO(&read_fds);
	FD_ZERO(&write_fds);

	ip = NULL;

	fdmax = listener;

  /* print out each peer */
  for (i=0; i<peers->val.s.i; i+=6) {
    /* construct the port */
    unsigned short port_tmp;
    unsigned short byte_1 = *((unsigned char *)&peer_str[i+4]) << 8;
    unsigned short byte_2 = *((unsigned char *)&peer_str[i+5]);
    port_tmp = byte_1 + byte_2;

    struct peer_connection *curr = malloc(sizeof(struct peer_connection));
    curr->ip = (unsigned char *) malloc(sizeof(unsigned char *) * 4);
    curr->ip[0]=*((unsigned char *)&peer_str[i+0]);
    curr->ip[1]=*((unsigned char *)&peer_str[i+1]);
    curr->ip[2]=*((unsigned char *)&peer_str[i+2]);
    curr->ip[3]=*((unsigned char *)&peer_str[i+3]);
    curr->port = port_tmp;
    curr->am_choked = 1;
		curr->am_interested = 0;
		curr->peer_choked = 1;
		curr->peer_interested = 0;
		curr->handshake_received = 0;
		curr->handshake_sent = 0;
		curr->bitset_len = total_pieces;
		curr->bitset = Create_Bit_Set(total_pieces);
    curr->interested_sent = 0;
    curr->piece_request_sent = 0;
    curr->data_length = 0;
    curr->incomplete_msg_data = NULL;
    curr->write_data = NULL;

		if (ip != NULL) {
			free(ip);
			ip = NULL;
		}
    ip = malloc(7);

    ret_val = asprintf((char **) &ip, "%u.%u.%u.%u", *((unsigned char *)&peer_str[i+0]), *((unsigned char *)&peer_str[i+1]), *((unsigned char *)&peer_str[i+2]), 
	   *((unsigned char *)&peer_str[i+3]));

    if (ret_val < 0) {
      perror("asprintf");
    }

    memset(&ip_addr, 0, sizeof(ip_addr));

    inet_pton(AF_INET, (const char *) ip, &(ip_addr.sin_addr));

  	ip_addr.sin_family = AF_INET;
  	ip_addr.sin_port = htons(port_tmp);
  	ip_addr_len = sizeof(struct sockaddr);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    curr->socket_num = sockfd;
    FD_SET(sockfd, &master);

    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    int retval = connect(sockfd, (struct sockaddr *) &ip_addr, sizeof(ip_addr));
    curr->socket_connected = 1;

    if (retval == 0) {
   		if (write(i, handshake, 68) == -1) { 
    		perror("Write error"); 
  		}
  		curr->handshake_sent = 1;
    } else if (retval == -1) {
    	if (errno == EINPROGRESS) {
    		FD_SET(sockfd, &write_fds);
    		FD_SET(sockfd, &master);
    		curr->handshake_sent = 0;
    	}
    }

    if (sockfd > fdmax) {
			fdmax = sockfd;
		}

    Add_To_Back_Of_list(peer_conns, curr);

  }

	FD_SET(listener, &master);

	for (;;) {

		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		FD_ZERO(&error_fds);

		FD_SET(listener, &read_fds);

		int tmp_max=0;

		for (i=0; i <= fdmax; i++) {
			peer_connection *conn = find_connection(i);
			if (conn != NULL) {
        if (!(conn->handshake_sent) && conn->handshake_received && conn->socket_connected) {
					// for server side --> received handshake, ready to send
					FD_SET(i, &read_fds);
					FD_SET(i, &error_fds);
					if (i > tmp_max) {
						tmp_max = i;
					}
				} else if (!(conn->handshake_sent) && !(conn->handshake_received) && conn->socket_connected) {
					// for client side --> waiting to write and receive handshake
					FD_SET(i, &write_fds);
					FD_SET(i, &error_fds);
					if (i > tmp_max) {
						tmp_max = i;
					}
				} else if (conn->handshake_sent && conn->handshake_received && conn->socket_connected) {
					// for client side (or server side) --> gave and received handshake, so ready to read more data
          if (conn->data_length > 0) {
            FD_SET(i, &write_fds);
          }
					FD_SET(i, &read_fds);
					FD_SET(i, &error_fds);
					if (i > tmp_max) {
						tmp_max = i;
					}
				} else if (conn->handshake_sent && !(conn->handshake_received) && conn->socket_connected) {
					// waiting to get handshake back
					FD_SET(i, &read_fds);
					FD_SET(i, &error_fds);
					if (i > tmp_max) {
						tmp_max = i;
					}
				}

        //if (conn != NULL && conn->write_data != NULL && conn->socket_connected) {
        /*if (conn != NULL && conn->data_length > 0 && conn->socket_connected) {
          FD_SET(i, &write_fds);
          FD_SET(i, &error_fds);
          if (i > tmp_max) {
            tmp_max = i;
          }
        }*/ 

			} else if (i==listener) {
				FD_SET(i, &read_fds);
				FD_SET(i, &error_fds);
				if (i > tmp_max) {
						tmp_max = i;
					}
			}

		}

		fdmax = tmp_max;

		gettimeofday(&current, NULL);
		remaining.tv_sec = start.tv_sec + 60 - current.tv_sec;
		remaining.tv_usec = 0;

		int ret;

		if ((ret = select(fdmax+1, &read_fds, &write_fds, &error_fds, &remaining)) <= 0) {
				if (ret == -1) {
					perror("select");
					continue;
				} else if (ret == 0) {
					exit_loop = 1;
				}
		}

		if (exit_loop) {
			break;
		}

		for(i = 0; i <= fdmax; i++) {
			//memset(buf, 0, strlen(buf));
      memset(buf, 0, 1024);
			if (FD_ISSET(i, &error_fds)) {
				peer_connection *conn = find_connection(i);
				perror("error fd");
				FD_CLR(i, &read_fds);
				FD_CLR(i, &master);
				FD_CLR(i, &write_fds);
				FD_CLR(i, &error_fds);
				close(i);
				conn->socket_connected = 0;
				continue;
			}
			if (FD_ISSET(i, &read_fds)) {
				if (i == listener) {
					addrlen = sizeof(remoteaddr);

					// new connection on the server socket

					if ((new_fd = accept(listener, (struct sockaddr *) &remoteaddr, &addrlen)) == -1) {
						perror("accept");
					} else {
						FD_SET(new_fd, &master);
						FD_SET(new_fd, &read_fds);

						struct sockaddr_in peer;
						int peer_len = sizeof(peer);

						getpeername(new_fd, (struct sockaddr *) &peer, (socklen_t *) &peer_len);

						// populate a peer_connection node

						peer_connection *conn = malloc(sizeof(struct peer_connection));

						conn->socket_num = new_fd;
						conn->ip = malloc(4);
						conn->ip = (unsigned char *) inet_ntoa(peer.sin_addr);
						conn->port = peer.sin_port;
						conn->am_choked = 1;
						conn->am_interested = 0;
						conn->peer_choked = 1;
						conn->peer_interested = 0;
						conn->handshake_received = 0;
						conn->handshake_sent = 0;
						conn->socket_connected = 1;
            conn->interested_sent = 0;
            conn->piece_request_sent = 0;
            conn->incomplete_msg_data = NULL;
            conn->write_data = NULL;
            conn->data_length = 0;

            conn->bitset_len = total_pieces;
            conn->bitset = Create_Bit_Set(total_pieces);

						Add_To_Back_Of_list(peer_conns, conn);						

						if (new_fd > fdmax) {
							fdmax = new_fd;
						}
					}
				} else {
					bytes_read = 0;
					peer_connection *conn = find_connection(i);

          if (conn != NULL && conn->incomplete_msg_data == NULL) {
            conn->total_bytes = 0;
            conn->incomplete_msg_data = malloc(BUFSIZ * 20);
          } else if (conn != NULL && conn->incomplete_msg_data != NULL) {
						process_data(conn, handshake, torrent_name, piece_len, piece_array);
					}

          bytes_read = read(i, ((conn->incomplete_msg_data) + conn->total_bytes), BUFSIZ * 20);

          if (bytes_read <= 0) {
            perror("read");
            FD_CLR(i, &read_fds);
            FD_CLR(i, &master);
            close(i);
            conn->socket_connected = 0;
            continue;
          }

          conn->total_bytes += bytes_read;
          conn->bytes_read = bytes_read;

					if (conn->incomplete_msg_data != NULL) {
            if (memcmp(conn->incomplete_msg_data, "exit\n", 5) == 0) {
    					exit_loop=1;
    					FD_CLR(i, &read_fds);
    					FD_CLR(i, &master);
    					close(i);
    					break;
    				} else {
    					process_data(conn, handshake, torrent_name, piece_len, piece_array);
    				} 
          }

				}
			}
			if (FD_ISSET(i, &write_fds)) {
				peer_connection *conn = find_connection(i);

				if (!(conn->handshake_sent) && !(conn->handshake_received)) {

					int error;
					socklen_t int_size = sizeof(int);
					getsockopt(i, SOL_SOCKET, SO_ERROR, (void *) &error, &int_size);
					if (error > 0) {
						perror("Write error"); 
						FD_CLR(i, &read_fds);
						FD_CLR(i, &write_fds);
						FD_CLR(i, &master);
						close(i);
						conn->socket_connected = 0;
						continue;
					}

					// if connect() successful, send the handshake
					if (write(i, handshake, 68) == -1) { 
						perror("Write error"); 
						FD_CLR(i, &read_fds);
						FD_CLR(i, &master);
						close(i);
						conn->socket_connected = 0;
						continue;
					}

				 	// If socket is not connected, try and connect and send handshake
					// Otherwise, drop it from the list (client side)

					// set socket to non-blocking
					int opts = fcntl(i, F_GETFL);
					opts |= O_NONBLOCK;
					fcntl(i, F_SETFL, opts);
					// update state
					conn->handshake_sent = 1;

					FD_CLR(i, &write_fds);
					FD_SET(i, &read_fds);

				} else if (conn->socket_connected && conn->data_length > 0) {
          int num_written = 0;
          num_written = write(conn->socket_num, conn->write_data, conn->data_length);
          if (num_written == -1) {
            perror("Write error");
            conn->socket_connected = 0;
            free(conn->write_data);
            conn->write_data = NULL;
            conn->data_length = 0;
            FD_CLR(i, &write_fds);
          } else {
            conn->data_length -= num_written;
            if (conn->data_length == 0) {
              free(conn->write_data);
              conn->write_data = NULL;
              FD_CLR(i, &write_fds);
            }
          }
        }
			}
		}
	}

	/* print out all peers */
	struct peer_connection *curr = Get_Front_Of_list(peer_conns);
	while (curr != NULL) {
    printf("> %u.%u.%u.%u:%u ", *((unsigned char *)&(curr->ip)[0]), *((unsigned char *)&(curr->ip)[1]), *((unsigned char *)&(curr->ip)[2]), 
	   *((unsigned char *)&(curr->ip)[3]), curr->port); 
    Print_Bit_Set(curr->bitset, total_pieces);
    printf("\n");
    close(curr->socket_num);
    curr = Get_Next_In_list(curr);
  }

  /* construct the GET request again */
  free(get_request);
  get_request = NULL;

  ret_val = asprintf(&get_request, "GET /%s?info_hash=%s&peer_id=%s&port=%d&uploaded=0&downloaded=0&left=%ld&compact=1&event=stopped HTTP/1.1\r\nHost:%s\r\n\r\n",
	   path_final, url_encode, peer_id, ntohs(bind_addr.sin_port), left, host);

  if (ret_val < 0) {
    perror("asprintf");
  }

  /* connect with host again */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(host, port, &hints, &result) != 0) { 
    fprintf(stderr, "Could not find hostname.\n"); 
  }

  for(p = result; p != NULL; p = p->ai_next) {
    sockfd = socket(p->ai_family, p->ai_socktype, 0);
    if (sockfd == -1) {
      continue; 
    }
    if (connect(sockfd, p->ai_addr, p->ai_addrlen) != -1) { 
      break; 
    }

    close(sockfd); 
  }

  if (p == NULL) {
    fprintf(stderr, "Could not connect\n"); 
  }

  if (write(sockfd, get_request, strlen(get_request)) == -1) { 
    perror("Write error"); 
  }

  close(sockfd);
  exit(EXIT_SUCCESS);

}
