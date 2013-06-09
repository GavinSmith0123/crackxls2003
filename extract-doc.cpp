/* Copyright (C) 2013 Gavin Smith
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <list>
#include <string>

#include <string.h>

#include "pole.h"

// Extract encryption data from Microsoft Word file
extern "C" void extract_doc(const char *file_name, unsigned char *record_out) {
  int n; // Used for number of bytes read
  POLE::Storage* storage = new POLE::Storage(file_name );
  storage->open();
  if( storage->result() != POLE::Storage::Ok )
  {
    std::cout << "Error on file " << std::endl;
    exit(1);
    return;
  }

  // Check File Information Block to see if document is encrypted
  POLE::Stream* stream = new POLE::Stream( storage, "WordDocument" );
  if (!stream || stream->fail() ) {
	std::cerr << "Could not open stream\n";
	return;
  }

  // FibBase should be at the beginning of the WordDocument stream
  unsigned char wIdent[2];
  n = stream->read(wIdent, 2);
  if (n != 2) return;

  if (! (wIdent[0] == 0xEC && wIdent[1] == 0xA5 )) {
    std::cerr << "FibBase not found\n";
  } else {
    std::cerr << "FibBase found\n";
  }

  return;


  while (1) {
	int n; //number of bytes read;

	// read record_id and record_size
	unsigned char id_and_size[4];
	n = stream->read(id_and_size, 4);
	
	if (n < 4) return;
	
	int id = id_and_size[0] + (id_and_size[1] << 8);
	int size = id_and_size[2] + (id_and_size[3] << 8);
	// std::cerr << id << "/" << size << "\n";

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

