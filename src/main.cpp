#include <string>
#include <iostream>
#include <DNSMessage.hpp>

using namespace std;

int main() {
    string rawDns;
    string line;
    
    cout << "Please enter hex encoded DNS string. Type 'exit' to complete input:" << endl;

    while(getline(cin, line)) {
        line.erase(remove(line.begin(), line.end(), '\n'), line.end());
        if(line == "exit") {
            break;
        }

        rawDns.append(line);
    }

    DNSMessage decodedData(rawDns);
    decodedData.printData();
    
    return 0;
}