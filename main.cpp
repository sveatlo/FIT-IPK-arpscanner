#include <iostream>
#include <unistd.h>
#include "Utils.h"
#include "ARPScanner.h"

using namespace std;

int main(int argc, char** argv) {
    if(getuid()) {
        Utils::print_error(0);
    } else if(argc != 5) {
        Utils::print_error(1);
    }

    string interface, output_file;
    char ch;
    while((ch = getopt(argc, argv, "i:f:")) != -1) {
        switch (ch) {
            case 'i':
                interface = string(optarg);
                break;
            case 'f':
                output_file = string(optarg);
                break;
            default:
                cerr << "Invalid argument" << endl;
                return -1;
        }
    }
    argc -= optind;

    if(argc > 0) {
        Utils::print_error(1);
    }

    ARPScanner *s = new ARPScanner(interface, output_file);
    delete s;

    return 0;
}
