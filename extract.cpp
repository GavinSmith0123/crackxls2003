#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <list>
#include <string>

#include <string.h>

#include "pole.h"


extern "C" void extract(char *file_name, unsigned char *record_out) {
  POLE::Storage* storage = new POLE::Storage(file_name );
  storage->open();
  if( storage->result() != POLE::Storage::Ok )
  {
    std::cout << "Error on file " << std::endl;
    exit(1);
    return;
  }

  int record_id, record_size;

  POLE::Stream* stream = new POLE::Stream( storage, "Workbook" );
  if (!stream || stream->fail() ) {
	std::cerr << "Could not open stream\n";
	return;
  }

  while (1) {
	int n; //number of bytes read;

	// read record_id and record_size
	unsigned char id_and_size[4];
	n = stream->read(id_and_size, 4);
	
	if (n < 4) return;
	
	int id = id_and_size[0] + (id_and_size[1] << 8);
	int size = id_and_size[2] + (id_and_size[3] << 8);
	std::cerr << id << "/" << size << "\n";

	switch (id) {
	case 0x002f: //FilePass
		{
		// extract data
		n = stream->read(record_out, size);
		return;
		}
	default:
		// advance to next record
		stream->seek(stream->tell() + size);
		if (stream->eof()) return;
	}
	  
  }
}

