#include <string>
#include <vector>

using namespace std;


// Defines every error thrown during DNS name validation
enum dnsNameError { VALID, INVALID_NAME_ERROR, NUMERIC_NAME_ERROR, INVALID_CHAR_ERROR };

// DNS Flag section of the header split into bit fields
struct DNSFlags {
    unsigned char QR : 1;
    unsigned char OPCODE : 4;
    unsigned char AA : 1;
    unsigned char TC : 1;
    unsigned char RD : 1;
    unsigned char RA : 1;
    unsigned char Z : 3;
    unsigned char RCODE : 4;
};

// Defines data stored by all question records
struct DNSQuestion {
    string qName;
    unsigned int qType;
    unsigned int qClass;
};

// Defines data stored by all resource records
struct ResourceRecord {
    string rName;
    unsigned int rType;
    unsigned int rClass;
    signed int rTtl;
    unsigned int rdLength;    
    string rData;
};

// Stores all DNS Message data and allows printing of the data
class DNSMessage {
    public:
        DNSMessage();
        DNSMessage(string hexData);
        
        void printData();
        
    private:
        unsigned int dnsID;
        DNSFlags headerFlags;
        unsigned int qdCount;
        unsigned int anCount;
        unsigned int nsCount;
        unsigned int arCount;

        vector<DNSQuestion> questions;
        vector<ResourceRecord> answers;
        vector<ResourceRecord> authority;
        vector<ResourceRecord> additional;

        void parseHeader(string& hexData, int& begin);
        void parseQuestions(string& hexData, int& begin);
        void parseResourceRecords(string& hexData, int& begin);

        string printableHeader();
        string printableQuestions();
        string printableResourceRecords();

        void parseRRData(string& hexData, int& begin, ResourceRecord& dataRecord);
        string extractRawHex(string& hexString);
        string extractName(string& hexData, int& begin);
        dnsNameError validateName(string dnsName);
};