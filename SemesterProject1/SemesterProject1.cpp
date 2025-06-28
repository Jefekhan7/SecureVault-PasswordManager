#include<iostream>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/exception.h>
#include <string>
#include <sstream>
#include <conio.h>
#include <vector>
#include <map>
#include <list>
#include <thread>
#include <iomanip>
#include <openssl/evp.h>

using namespace std;



string key = "akpz"; // the default key for encryption of the passwords


// convert the password into   hexa decimal string  .. 256bit = 256/8 = 32byte / 1 byte = 8bit / 1hex =4bit / so total 64 chracters

string sha256(const string& input) { // use advance api for crypto operation . the evp is envelop that have all the cryptographic function in under it. the md is the type of message digest which we want to perform on the data
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input.c_str(), input.size()); // convert it into c style string only work with that
    EVP_DigestFinal_ex(ctx, hash, &lengthOfHash); // start the excution
    EVP_MD_CTX_free(ctx);//free memroy 

    stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// for password comparing we will use the compare function
bool compareSHA256(const string& inputhashed, const string& expectedHash) {

    return inputhashed == expectedHash;       // Compare with stored hash
}


string generateFullKey(string plainText, string key)
{
    string fullKey = key;
    while (fullKey.length() < plainText.length()) {
        fullKey += key;
    }
    return fullKey.substr(0, plainText.length());
}

string encryption(string plainText, string key)
{

    int textnum, keynum;
    string cipherText;
    string fullKey = generateFullKey(plainText, key);

    for (int n = 0; n < plainText.length(); n++) {
        if (isalpha(plainText[n])) {
            if (isupper(plainText[n])) {
                textnum = plainText[n] - 'A';
                keynum = fullKey[n] - 'A';
                int mappedNumber = (textnum + keynum) % 26;
                char mapAlpha = mappedNumber + 'A';
                cipherText += mapAlpha;
            }
            else if (islower(plainText[n])) {
                textnum = plainText[n] - 'a';
                keynum = fullKey[n] - 'a';
                int mappedNumber = (textnum + keynum) % 26;
                char mapAlpha = mappedNumber + 'a';
                cipherText += mapAlpha;
            }
        }
        else if (isblank(plainText[n])) {
            cipherText += "#";
        }
        else {

            cipherText += plainText[n];
        }
    }

    return cipherText;
}

string decryption(string& cipherText, string key)
{


    int textnum, keynum;
    string plainText;
    string fullKey = generateFullKey(cipherText, key);

    for (int n = 0; n < cipherText.length(); n++) {
        if (isalpha(cipherText[n])) {
            if (isupper(cipherText[n])) {
                textnum = cipherText[n] - 'A';
                keynum = fullKey[n] - 'A';
                int mappedNumber = (textnum - keynum + 26) % 26;
                char mapAlpha = mappedNumber + 'A';
                plainText += mapAlpha;
            }
            else if (islower(cipherText[n])) {
                textnum = cipherText[n] - 'a';
                keynum = fullKey[n] - 'a';
                int mappedNumber = (textnum - keynum + 26) % 26;
                char mapAlpha = mappedNumber + 'a';
                plainText += mapAlpha;
            }
        }
        else if (cipherText[n] == '#') {
            plainText += " ";
        }
        else {
            plainText += cipherText[n];

        }
    }
    return plainText;
}

class DatabaseManager {

public:
    sql::mysql::MySQL_Driver* driver;
    sql::Connection* con;

    DatabaseManager() // connect to the database 
    {
        try {
            driver = sql::mysql::get_mysql_driver_instance();
            con = driver->connect("tcp://127.0.0.3:3306", "root", "jefe7");
            con->setSchema("sec-vaultdb");

        }
        catch (sql::SQLException& e) {
            cerr << "SQL Error: " << e.what() << endl;
            cerr << "MySQL error code: " << e.getErrorCode() << endl;
        }
    }

    ~DatabaseManager()   // delete the connection
    {
        if (con)
            delete con;
    }

    // get latest user id from the database 
    int getLastUserId() {
        try {
            sql::Statement* stmt = con->createStatement();
            sql::ResultSet* res = stmt->executeQuery("SELECT MAX(user_id) FROM users");

            int maxId = 0;
            if (res->next()) {
                maxId = res->getInt(1);
            }


            delete res;
            delete stmt;

            return maxId;
        }
        catch (sql::SQLException& e) {
            cout << "Error getting max user ID: " << e.what() << endl;
            return 0;
        }

    }

    // insert into database 
    void  insertUser(int userID, string fullName, string masterPassword, string securityQuestion)
    {


        try {
            // Prepare the insert statement
            sql::PreparedStatement* pstmt = con->prepareStatement(
                "INSERT INTO users (user_id, full_name, master_password, security_question) "
                "VALUES (?, ?, ?, ?)"
            );

            pstmt->setInt(1, userID);
            pstmt->setString(2, fullName);
            pstmt->setString(3, masterPassword);
            pstmt->setString(4, securityQuestion);

            int result = pstmt->executeUpdate();
            delete pstmt;


            cout << "\n \033[1;32m Registeration successful \033[0m! Your User ID is: " << userID;
            cin.ignore();
        }
        catch (sql::SQLException& e) {

            cout << "\n \033[1;31mError! Registeration failed due to \033 " << e.what();
            cin.ignore();

        }


    }


    bool  updateUser(int userID, string fullName, string masterPassword, string securityQuestion)
    {

        try {
            // Prepare the insert statement
            sql::PreparedStatement* pstmt = con->prepareStatement(
                "UPDATE users SET "
                "full_name = ? ,"
                "master_password = ?, "
                "security_question = ? "
                "WHERE user_id = ? "
            );

            pstmt->setString(1, fullName);
            pstmt->setString(2, masterPassword);
            pstmt->setString(3, securityQuestion);
            pstmt->setInt(4, userID);

            int result = pstmt->executeUpdate();
            delete pstmt;


            return true;

            cout << "\nClick Enter ";
            cin.ignore();
        }
        catch (sql::SQLException& e) {

            cout << "\n \033[1;31mError! Registeration failed due to \033 " << e.what() << endl;

            return false;
        }


    }

};


class PasswordsManager {
public:
    sql::mysql::MySQL_Driver* driver;
    sql::Connection* con;

    PasswordsManager() {
        try {
            driver = sql::mysql::get_mysql_driver_instance();
            con = driver->connect("tcp://127.0.0.3:3306", "root", "jefe7");
            con->setSchema("sec-vaultdb");


        }
        catch (sql::SQLException& e) {
            cerr << "SQL Error: " << e.what() << endl;
            cerr << "MySQL error code: " << e.getErrorCode() << endl;
        }
    }

    ~PasswordsManager()
    {
        if (con)
        {

            con = nullptr;
        }
    }

    // **this is returning last credid not user
    int getLastUserId() {
        try {
            sql::Statement* stmt = con->createStatement();
            sql::ResultSet* res = stmt->executeQuery("SELECT MAX(credID) FROM userpasswords");

            int maxId = 0;
            if (res->next()) {
                maxId = res->getInt(1);
            }


            delete res;
            delete stmt;

            return maxId;
        }
        catch (sql::SQLException& e) {
            cout << "Error getting credential ID: " << e.what() << endl;
            return 0;
        }

    }

    void  insertPassword(int credId, int userID, string platform, string username, string password)
    {
        try {
            // Prepare the insert statement
            sql::PreparedStatement* pstmt = con->prepareStatement(
                "INSERT INTO userpasswords (credID,userID, platformName, username, password) "
                "VALUES (?,?,?, ?, ?)"
            );

            pstmt->setInt(1, credId);
            pstmt->setInt(2, userID);
            pstmt->setString(3, platform);
            pstmt->setString(4, username);
            pstmt->setString(5, password);

            int result = pstmt->executeUpdate();
            delete pstmt;


            cout << "\n \033[1;32m Password Added successfully! \033[0m ";
            cin.ignore();
        }
        catch (sql::SQLException& e) {

            cout << "\n \033[1;31mError! Password failed to add  \033 " << e.what();
            cin.ignore();

        }

    }


    bool updateCredential(int credID, string  newPlatform, string  newUsername, string newPassword) {
        try {
            sql::PreparedStatement* pstmt = con->prepareStatement(
                "UPDATE userpasswords SET "
                "platformName = ?, "
                "username = ?, "
                "password = ? "
                "WHERE credID = ?"
            );

            pstmt->setString(1, newPlatform);
            pstmt->setString(2, newUsername);
            pstmt->setString(3, newPassword);
            pstmt->setInt(4, credID);

            int rowsAffected = pstmt->executeUpdate();
            delete pstmt;

            return rowsAffected > 0;
        }
        catch (sql::SQLException& e) {
            cerr << "Error updating credential: " << e.what();
            return false;
        }
    }

    bool  deleteuserPassword(int CredID)
    {
        try {



            sql::PreparedStatement* pstmt = con->prepareStatement(
                "DELETE FROM userpasswords WHERE credID = ?"
            );

            pstmt->setInt(1, CredID);
            int affectedRows = pstmt->executeUpdate();
            delete pstmt;  // Clean up here

            return affectedRows > 0;


        }
        catch (sql::SQLException& e) {

            cout << "\033[1;31mError deleting Password: \033[0m" << e.what() << endl;
            return false;

        }
    }

};

class NotesManager {
public:
    sql::mysql::MySQL_Driver* driver;
    sql::Connection* con;


    NotesManager()
    {
        try {
            driver = sql::mysql::get_mysql_driver_instance();
            con = driver->connect("tcp://127.0.0.3:3306", "root", "jefe7");
            con->setSchema("sec-vaultdb");


        }
        catch (sql::SQLException& e) {
            cerr << "SQL Error: " << e.what() << endl;
            cerr << "MySQL error code: " << e.getErrorCode() << endl;
        }
    }

    ~NotesManager()
    {
        if (con)
        {

            con = nullptr;
        }
    }

    int getlastnotId() {
        try {
            sql::Statement* stmt = con->createStatement();
            sql::ResultSet* res = stmt->executeQuery("SELECT MAX(NoteID) FROM usernotes");

            int maxId = 0;
            if (res->next()) {
                maxId = res->getInt(1);
            }


            delete res;
            delete stmt;

            return maxId;
        }
        catch (sql::SQLException& e) {
            cout << "Error getting credential ID: " << e.what() << endl;
            return 0;
        }

    }

    void insertNote(int NoteID, int userID, list<string> content)
    {

        try {

            sql::PreparedStatement* pstmt = con->prepareStatement(
                "INSERT INTO usernotes(NoteID, userID, Content) VALUES (?, ?, ?)"
            );


            string fullcontent;

            for (const auto& line : content) {
                fullcontent += line + "\n";
            }

            if (!fullcontent.empty()) {
                fullcontent.pop_back(); //remove new lines

            }





            pstmt->setInt(1, NoteID);
            pstmt->setInt(2, userID);
            pstmt->setString(3, fullcontent);


            int result = pstmt->executeUpdate();
            delete pstmt;


            cout << " \033[1;32m Note Added successfuly \033[0m ";
        }
        catch (sql::SQLException& e) {

            cout << "\n \033[1;31mError!  Note failed to add  \033 " << e.what();
            cin.ignore();

        }




    }

    bool updateNote(int NoteID, const list<string>& content)
    {
        try {

            string fullcontent;
            for (const auto& line : content) {
                fullcontent += line + "\n";
            }


            if (!fullcontent.empty()) {
                fullcontent.erase(fullcontent.length() - 1);
            }


            sql::PreparedStatement* pstmt = con->prepareStatement(
                "UPDATE usernotes SET Content = ? WHERE NoteID = ?"
            );

            pstmt->setString(1, fullcontent);
            pstmt->setInt(2, NoteID);

            int affectedRows = pstmt->executeUpdate();
            delete pstmt;


            return affectedRows > 0;
        }
        catch (sql::SQLException& e) {
            cout << "Error updating note: " << e.what() << endl;
            return false;
        }
    }
    bool delNote(int NoteID)
    {
        try {

            std::unique_ptr<sql::PreparedStatement> pstmt(
                con->prepareStatement("DELETE FROM usernotes WHERE NoteID = ?")
            );
            pstmt->setInt(1, NoteID);

            int result = pstmt->executeUpdate();


            con->commit();
            con->setAutoCommit(true);

            return result > 0;
        }
        catch (sql::SQLException& e) {

            cout << "\033[1;31mError deleting note ID " << NoteID << ": " << e.what() << "\033[0m" << endl;
            return false;
        }
    }

};


// to access by all function below i define masked password here

string getMaskedPassword()
{
    string password;
    char ch;

    while (true)
    {
        ch = _getch();

        if (ch == 13)
        { // Enter key (ASCII 13)
            cout << endl;
            break;
        }
        else if (ch == 8)
        { // Backspace (ASCII 8)
            if (!password.empty())
            {
                cout << "\b \b";     // Move back, overwrite with space, move back again
                password.pop_back(); // remove from the actual password
            }
        }
        else
        {
            password += ch;
            cout << '*';
        }
    }
    return password;
}



class Passwords
{
private:
    static int totalPasswords;
    int CredId;
    string platformName;
    string userName;
    string password;

public:
    Passwords()
    {
        totalPasswords++;
    }


    void setCredno(int cred)
    {
        CredId = cred;
    }
    void setPlatform(string p)
    {
        platformName = p;
    }
    void setUsername(string u)
    {
        userName = u;
    }
    void setPassword(string ps)
    {
        password = ps;
    }

    string getplatfromName()
    {
        return platformName;
    }
    int getCredId()
    {
        return CredId;
    }
    string getUsername()
    {
        return userName;
    }
    string getPassword() const
    {
        return password;
    }

    void displayPasswords() const
    {
        cout << "Platform : " << platformName << endl;
        cout << "Phone/Email :" << userName << endl;
        cout << "Password : " << password << endl;
    }

};
int Passwords::totalPasswords = 0;

class Notes {
public:

    list<string> Note;
    int NoteID;

    void setNoteContent()
    {
        string line;

        while (true)
        {
            getline(cin, line);
            if (line == "!")
                break;
            Note.push_back(line);
        }
    }

    void setNoteContent(string n)
    {
        istringstream iss(n);
        string line;
        while (getline(iss, line)) {
            Note.push_back(line);
        }
    }

    Notes()
    {

    }

    void setNoteid(int n)
    {
        NoteID = n;
    }

    list<string> getNoteContent()
    {
        return Note;
    }

    int getnoteid()
    {
        return NoteID;
    }

    void add(int noteId)
    {
        system("cls");
        cout << "\033[1;36m--------------------------------------------------------------------------------------------------------" << endl;
        cout << "            Enter your secret note (type '!' to finish):    \033[1:37m   NoteID: " << noteId << "                  " << endl;
        cout << "--------------------------------------------------------------------------------------------------------\033[0m" << endl;


        string line;

        while (true)
        {
            getline(cin, line);
            if (line == "!")
                break;
            Note.push_back(line);
        }

    }


    void edit()
    {
        system("cls");
        cout << "\033[1;36m--------------------------------------------------------------------------------------------------------" << endl;
        cout << "                               ~  My Current Notes  ~                                                     " << endl;
        cout << "--------------------------------------------------------------------------------------------------------\033[0m" << endl;
        if (Note.empty())
        {
            cout << "\n\033[1;31m No notes to edit. \033[0m";
            cin.ignore();
            return;
        }


        int index = 0;
        for (const auto& line : Note)
        {
            cout << "\033[1;36m]" << index << ": \033[0m" << line << endl;
            index++;
        }

        cout << "\n\033[1;36m--------------------------------------------------------------------------------------------------------\033[0m" << endl;
        int choice;
        cout << "\n\033[1;36mEnter the line number to edit:\033[0m ";
        cin >> choice;
        cin.ignore();
        if (choice < 0 || choice >= Note.size())
        {
            cout << "\033[1;31m Invalid line number. \033[0m" << endl;
            return;
        }

        cout << "\n\033[1;36mEnter the new content for line " << choice << ": \033[0m";
        string newLine;
        getline(cin, newLine);

        auto it = Note.begin();
        advance(it, choice);
        *it = newLine;


    }

    void displayNote() const
    {
        list<string>::const_iterator it;
        for (it = Note.begin(); it != Note.end(); it++)
        {
            cout << *it << endl;
        }
    };


};


class Vault {

public:
    vector<Notes> userNotes;
    vector<Passwords> userPasswords;
    PasswordsManager pd;   // talk to database for passwords management
    NotesManager np;   // talk to database for notes management


    Vault()
    {

    }

    void addNote(int userID)
    {
        system("cls");
        Notes nt;
        if (np.getlastnotId() <= 0)
        {
            nt.setNoteid(1); // id = 1  if no  record
        }
        int NoteID = np.getlastnotId() + 1;
        nt.add(NoteID); // will add note

        np.insertNote(NoteID, userID, nt.getNoteContent());

        cin.ignore();
    }

    //will load all the notes for user to the the userNotes;
    void loadAllNotes(int userID)
    {
        userNotes.clear();
        sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();
        sql::Connection* con = driver->connect("tcp://127.0.0.3:3306", "root", "jefe7");
        con->setSchema("sec-vaultdb");

        sql::PreparedStatement* pstmt = con->prepareStatement("SELECT * FROM usernotes WHERE userID = ?");
        pstmt->setInt(1, userID);

        sql::ResultSet* res = pstmt->executeQuery();

        while (res->next()) {
            Notes nt;
            string content;

            nt.setNoteid(res->getInt("NoteID"));
            content = res->getString("Content");
            nt.setNoteContent(content);
            userNotes.push_back(nt);
        }


        delete res;
        delete pstmt;
        delete con;
    }

    void editNote(int userID)
    {
        system("cls");
        cout << "\033[1;36m--------------------------------------------------------------------------------------------------------" << endl;
        cout << "                               ~  My Current Notes  ~                                                     " << endl;
        cout << "--------------------------------------------------------------------------------------------------------\033[0m" << endl;
        userNotes.clear();
        loadAllNotes(userID); //  remove & refresh

        int editID;
        cout << endl;

        if (userNotes.empty())
        {
            cout << "\n033[1;31m No Notes to Edit \033[0m ";
            cin.ignore();
            cin.get();
            return;
        }

        for (Notes& NT : userNotes)
        {
            cout << "\033[1;36m  " << NT.getnoteid() << "  \033[0m";
            int wordCount = 0;
            int maxWords = 5;
            for (const auto& line : NT.getNoteContent())
            {
                stringstream ss(line);
                string word;
                while (ss >> word && wordCount < maxWords)
                {
                    cout << word << " ";
                    wordCount++;
                }
                if (wordCount >= maxWords)
                    break;
            }
            cout << "..." << endl;
        }

        cout << "\n\033[1;37m Enter NoteId to edit: \033m ";
        cin >> editID;
        cin.ignore();
        bool edited = false;
        for (auto it = userNotes.begin(); it != userNotes.end(); ++it)
        {
            if (it->getnoteid() == editID)
            {
                it->edit();
                if (np.updateNote(editID, it->getNoteContent()))
                {

                    edited = true;
                    break;
                }

            }

        }

        if (edited)
        {
            cout << "\n \033[1;32m Note Edited successfuly \033[0m ";
            cin.ignore();
            cin.get();
        }
        else {

            cout << "\n\033[1;31m No Note Found! \033[0m ";
            cin.ignore();


        }

    }

    void delNote(int userID)
    {
        system("cls");
        userNotes.clear();
        loadAllNotes(userID); //  remove & refresh

        cout << "\033[1;36m--------------------------------------------------------------------------------------------------------" << endl;
        cout << "                               ~  My Current Notes  ~                                                     " << endl;
        cout << "--------------------------------------------------------------------------------------------------------\033[0m" << endl;


        if (userNotes.empty())
        {
            cout << "\n033[1;31m No Notes to Delete \033[0m ";
            cin.ignore();
            cin.get();
            return;
        }

        cout << endl;
        for (Notes& NT : userNotes)
        {
            cout << "\033[1;36m  " << NT.getnoteid() << "  \033[0m";
            int wordCount = 0;
            int maxWords = 5;
            for (const auto& line : NT.getNoteContent())
            {
                stringstream ss(line);
                string word;
                while (ss >> word && wordCount < maxWords)
                {
                    cout << word << " ";
                    wordCount++;
                }
                if (wordCount >= maxWords)
                    break;
            }
            cout << "..." << endl;
        }


        cout << "\n\033[1;37m Enter Note id to Delete \033[0m";



        int delId;
        cin >> delId;

        bool deleted = false;
        for (auto it = userNotes.begin(); it != userNotes.end(); ++it)
        {
            if (it->getnoteid() == delId)
            {
                userNotes.erase(it);
                // also deleted from the database 
                if (np.delNote(delId))
                {
                    deleted = true;
                    break;

                }
                else {
                    deleted = false;
                }
            }

        }

        if (deleted)
        {
            cout << "\n \033[1;32m Notes Deleted successfuly \033[0m";
            cin.ignore();
            cin.get();
        }
        else {

            cout << "\n\033[1;31m No Note Found! \033[0m ";
            cin.ignore();
            cin.get();

        }

    }

    void  showNotes(int userID)
    {
        system("cls");
        userNotes.clear();
        loadAllNotes(userID);

        cout << "\033[1;36m--------------------------------------------------------------------------------------------------------" << endl;
        cout << "                               ~  My Current Notes  ~                                                     " << endl;
        cout << "--------------------------------------------------------------------------------------------------------\033[0m" << endl;

        if (userNotes.empty())
        {
            cout << "\n\033[1;31m No Notes to show \033[0m ";
            cin.ignore();
            return;
        }
        cout << endl;

        for (Notes& NT : userNotes)
        {
            cout << " \033[1;36m  " << NT.getnoteid() << "  \033[0m";
            int wordCount = 0;
            int maxWords = 5;
            for (const auto& line : NT.getNoteContent())
            {
                stringstream ss(line);
                string word;
                while (ss >> word && wordCount < maxWords)
                {
                    cout << word << " ";
                    wordCount++;
                }
                if (wordCount >= maxWords)
                    break;
            }
            cout << "..." << endl;
        }
        cout << "\n \033[1;37m Enter Note ID to show Complete Note \033[0m";

        int showid;
        cin >> showid;
        cin.ignore();
        system("cls");

        cout << endl;

        for (auto it = userNotes.begin(); it != userNotes.end(); ++it)
        {
            if (it->getnoteid() == showid)
            {

                it->displayNote();

                break;
            }
        }



        cout << "\n\033[1;36m  Enter to Go back \033[0m";
        cin.clear();
        cin.get(); // Wait for ENTER key
        system("cls");
    }

    void usernotesMenu(int userID)
    {
        system("cls");
        loadAllNotes(userID);
        int choice;


        do {
            system("cls");
            cout << "\033[1;36m\n---------------------------------------------------" << endl;
            cout << "                    ~  My Notes ~                             " << endl;
            cout << "---------------------------------------------------\033[0m" << endl;
            cout << "\033[1;37m1 - Add Note " << endl;
            cout << "2 - Edit Note" << endl;
            cout << "3 - Delete Note" << endl;
            cout << "4 - Show Notes " << endl;
            cout << "0 - Back -> \033[0m" << endl;
            cout << "\033[1;36m--------------------------------------------------\033[0m" << endl;
            cout << "Enter your Choice : ";
            cin >> choice;


            switch (choice)
            {
            case 1:
            {
                addNote(userID);

            }break;

            case 2:
            {
                editNote(userID);
            }break;

            case 3:
            {
                delNote(userID);
            }break;

            case 4:
            {

                showNotes(userID);
            }break;

            case 5:
            {
                loadAllPasswords(userID);
                searchbyplatform();
            }

            default:
                cout << " ";
            }


        } while (choice != 0);
    }


    //*** Password managing here *** 

    // will load all user credentials to vectors container
    void loadAllPasswords(int userID) {
        userPasswords.clear();
        sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();
        sql::Connection* con = driver->connect("tcp://127.0.0.3:3306", "root", "jefe7");
        con->setSchema("sec-vaultdb");

        sql::PreparedStatement* pstmt = con->prepareStatement("SELECT * FROM userpasswords WHERE userID = ?");
        pstmt->setInt(1, userID);

        sql::ResultSet* res = pstmt->executeQuery();

        while (res->next()) {
            Passwords pass;
            pass.setCredno(res->getInt("credID"));
            pass.setPlatform(res->getString("platformName"));
            pass.setUsername(res->getString("username"));
            pass.setPassword(res->getString("password"));

            userPasswords.push_back(pass);
        }

        delete res;
        delete pstmt;
        delete con;
    }


    void addPassword(int userID)
    {
        system("cls");
        Passwords pass;
        string platformName, userName, password;
        if (pd.getLastUserId() <= 0)
        {
            pass.setCredno(1);
        }
        int CredID = pd.getLastUserId() + 1;

        cout << "\033[1;36m----------------------------------------------------" << endl;
        cout << "                 ~ Add Password ~               " << endl;
        cout << "----------------------------------------------------\033[0m" << endl;

        cout << "Enter Platform Name : ";
        getline(cin, platformName);
        cout << "\nEnter Phone/Email : ";
        getline(cin, userName);
        cout << "\nEnter Password : ";
        password = getMaskedPassword();
        string encryptedPassword = encryption(password, key);



        pass.setCredno(CredID);
        pass.setPlatform(platformName);
        pass.setUsername(userName);
        pass.setPassword(encryptedPassword);


        pd.insertPassword(CredID, userID, platformName, userName, encryptedPassword);
    }

    void updatePassword(int userID)
    {
        system("cls");
        loadAllPasswords(userID); // to show the latest record
        cout << "\033[1;36m----------------------------------------------------" << endl;
        cout << "                 ~ Selete Id to Update   ~               " << endl;
        cout << "----------------------------------------------------\033[0m" << endl;
        if (userPasswords.empty())
        {
            cout << " \033[1;31m No Passwords to edit. \033[0m";
            cin.ignore();
            return;
        }


        for (Passwords& pc : userPasswords)
        {
            cout << "\033[1;36m" << pc.getCredId() << " - \033[0m" << pc.getplatfromName() << "( \033[1;36m" << pc.getUsername() << "\033[0m)" << endl;
        }

        int editId;
        cout << endl;

        cin >> editId;
        cin.ignore();

        string encrytpedPassword;

        bool found = false;
        for (Passwords& pc : userPasswords)
        {
            if (pc.getCredId() == editId)
            {
                found = true;


                string platform, username, pwd;
                cout << "\n\033[1;37mEnter new Platform Name (leave empty to keep current): \033[0m";
                getline(cin, platform);
                cout << "\n\033[1;37mEnter new Username/Email (leave empty to keep current): \033[0m";
                getline(cin, username);
                cout << "\n\033[1;37mEnter new Password (leave empty to keep current): \033[0m";
                pwd = getMaskedPassword();


                // Update only if not empty
                if (!platform.empty())
                {

                    pc.setPlatform(platform);
                }


                if (!username.empty()) {
                    pc.setUsername(username);
                  }

                if (!pwd.empty()) {
                encrytpedPassword = encryption(pwd, key);
                pc.setPassword(encrytpedPassword);

            }
                //update to the new values enter 
                editId = pc.getCredId();
                platform = pc.getplatfromName();
                username = pc.getUsername();
                pwd = pc.getPassword();

                //move the password manager for sending to database
                if (pd.updateCredential(editId, platform, username, encrytpedPassword))
                {
                    cout << "\n \033[1;32m Password updated successfully! \033[0m";
                    cin.ignore();
                }


                break;
            }
        }

        if (!found)
        {
            cout << "\n \033[1;31m No passwords Found\033[0m  ";
            cin.ignore();

        }
    }

    void deletePassword(int userID)
    {
        system("cls");

        loadAllPasswords(userID); // to show the latest record
        cout << "\033[1;36m----------------------------------------------------" << endl;
        cout << "                 ~ Select Id to Delete ~               " << endl;
        cout << "----------------------------------------------------\033[0m" << endl;


        if (userPasswords.empty())
        {
            cout << "\033[1;31m No passwords to Delete.\033[0m";
            cin.ignore();
            return;
        }


        for (Passwords& pc : userPasswords)
        {
            cout << "\033[1;36m" << pc.getCredId() << " - \033[0m" << pc.getplatfromName() << "( \033[1;36m" << pc.getUsername() << "\033[0m)" << endl;
        }
        cout << endl;

        int DelId;


        cin >> DelId;


        if (pd.deleteuserPassword(DelId))
        {
            cout << "\n \033[1;32m Password Deleted successfully \033[0m ";
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cin.get();
        }
        else {
            cout << "\n \033[1;31m Password not Found! \033[0m ";
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cin.get();
        }


    }

    void  showpasswords()
    {
        system("cls");

        cout << "\n\033[1;36m------------------------------------------------------" << endl;
        cout << "\033[1;36m                Your Passwords : \033[0m             " << endl;
        cout << "\033[1;36m------------------------------------------------------\033[0m" << endl;

        for (auto &ps : userPasswords)
        {
            cout << "\nCredID : " << ps.getCredId() << endl;
            cout << "Platform: " << ps.getplatfromName() << endl;
            cout << "Username : " << ps.getUsername() << endl;
            string Password = ps.getPassword();
            string decryptedPassword = decryption(Password, key);
            cout << "Password : " << decryptedPassword<< "\033[0m" << endl;
            cout << " \033[1;36m ------------- \033[0m                 " << endl;
        }

        cout << "\nClick -> to go back ";
        cin.clear();
        cin.get(); // Wait for ENTER key
        system("cls");
    }

    void searchbyplatform()
    {
        // creating a temporary map . to store platform specifc passwords
        system("cls");
        string userInput;
        bool found = false;

        cout << "\n\033[1;36m------------------------------------------------------" << endl;
        cout << "\033[1;36m                Search platform passwords : \033[0m             " << endl;
        cout << "\033[1;36m------------------------------------------------------\033[0m" << endl;
        cout << "\n\033[1;37mEnter platform Name (case sensitive) : \033[0m";
        getline(cin, userInput);


        map<string, vector<Passwords>> platformMap;

        for (Passwords& cred : userPasswords)
        {
            platformMap[cred.getplatfromName()].push_back(cred);
        }

        for (auto& entry : platformMap)
        {
            if (entry.first == userInput) {
                found = true;
                cout << "\n\033[1;36m Platform: " << entry.first << "\033[0m" << endl;
                cout << "----------------------------" << endl;
                for (auto& cred : entry.second)
                {
                    cout << "Credential ID: " << cred.getCredId() << endl;
                    cout << "Username/Email: " << cred.getUsername() << endl;
                    string password = cred.getPassword();
                    string decryptedPassword = decryption(password, key);
                    cout << "Password: " << decryptedPassword << endl;
                    cout << "\033[1;36m---------------------------\033[0m" << endl;
                }
            }
        }

        if (!found)
        {

            cout << "\n\033[1;31mNo credentials found for platform: \033[0m" << userInput << endl;

        }


        cout << "\nClick -> to go back ";
        cin.clear();
        cin.get(); // Wait for ENTER key
        system("cls");
    }

    void userPasswordMenu(int userID)
    {

        userPasswords.clear(); // Remove & refresh
        loadAllPasswords(userID);
        int choice;
        do {
            system("cls");
            cout << "\033[1;36m-------------------------------------------------" << endl;
            cout << "                 ~ My Credentials ~               " << endl;
            cout << "-------------------------------------------------\033[0m" << endl;
            cout << "1 - Add New Password " << endl;
            cout << "2 - Update Password" << endl;
            cout << "3 - Delete Password" << endl;
            cout << "4 - Show All Passwords " << endl;
            cout << "5 - Search by platform " << endl;
            cout << "0 - Go Back -> " << endl;
            cout << "\033[1;36m--------------------------------------------------\033[0m" << endl;
            cin >> choice;
            cin.ignore();


            switch (choice)
            {
            case 1:
            {
                addPassword(userID);

            }break;

            case 2:
            {
                updatePassword(userID);
            }break;

            case 3:
            {
                deletePassword(userID);
            }break;

            case 4:
            {
                loadAllPasswords(userID);
                showpasswords();
            }break;

            case 5:
            {
                loadAllPasswords(userID);
                searchbyplatform();
            }

            default:
                cout << " ";
            }


        } while (choice != 0);
    }
};

class User {

private:
    static int Totaluser;
    int userID;
    string fullName;
    string securityQuestion;
    string masterPassword;
    string unhashedPass;
    Vault userVault;

public:

    User()
    {
        Totaluser++;
    }

    // set user data
    void setUserID(int id)
    {
        userID = id;
    }
    void setunhashedPassword(string inputpassword)
    {
        unhashedPass = inputpassword;
    }
    void setUserPassword(string pass)
    {
        masterPassword = pass;
    }

    void setFullname(string n)
    {
        fullName = n;
    }

    void setSecurityQuestion(string sc)
    {
        securityQuestion = sc;
    }

    void userInfo()
    {
        system("cls");
        string userinput;
        string hashedinput;
        cout << "\n\033[1:37m For security the system is asking for your master password : \033[0m ";
        userinput = getMaskedPassword();
        setunhashedPassword(userinput);
        hashedinput = sha256(userinput);
        if (masterPassword == hashedinput)
        {
            system("cls");
            cout << "\n\033[1;36m------------------------------------------------------" << endl;
            cout << "\033[1;36m                Your Info : \033[0m             " << endl;
            cout << "\033[1;36m------------------------------------------------------\033[0m\n" << endl;

            cout << "\033[1;37mUser ID: " << userID << endl;
            cout << "\nFull Name: " << fullName << endl;
            cout << "\nMaster Password: " << unhashedPass << endl;
            cout << "\nSecurity Answer to ( what is your favourite subject ) ? is:  " << securityQuestion << "\033[0m" << endl;

            cout << "\n  Click enter ! ";
            cin.ignore();
        }
        else {
            cout << "\n\033[1;31m Incorrect Password .\033[0m ";
            cout << "Click enter to go back ";
            cin.ignore();
            return;
        }
    }

    // get user data
    int getuserID() const { return userID; }
    string getfullname() const { return fullName; }
    string getmasterPassword() const { return masterPassword; }
    string getSecurityQuestion() const { return securityQuestion; }


    // user menu 

    void displayMenu()
    {
        int choice;
        do
        {
            system("cls");
            cout << "\033[1;36m\n----------------------------------------------------" << endl;
            cout << "              ~ Welcome, [ \033[\033[1;37m" << fullName << " \033[0m\033[1;36m]   \033[0m" << endl;
            cout << "\033[1;36m-----------------------------------------------------\033[0m" << endl;
            cout << "1 - MY Notes   " << endl;
            cout << "2 - MY Passwords   " << endl;
            cout << "3 - My Info   " << endl;
            cout << "0 - Logout   " << endl;
            cout << "\n\033[1;36m---------------------------------------------------- \033[0m" << endl;
            cout << "Enter your choice : ";
            cin >> choice;
            cin.ignore();

            switch (choice)
            {
            case 1:
            {
                userVault.usernotesMenu(userID);
            }break;

            case 2:
            {
                userVault.userPasswordMenu(userID);
            }break;

            case 3:
            {
                userInfo();
            }break;

            default:
                cout << " ";

            }
        } while (choice != 0);
    }
};
int User::Totaluser = 0;




// this class loads all the users from database into Logins // using in the database class doesnt allow  to access the user class
void loadAllUsers(map<int, User>& Logins) {


    sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();
    sql::Connection* con = driver->connect("tcp://127.0.0.3:3306", "root", "jefe7");
    con->setSchema("sec-vaultdb");

    sql::Statement* stmt = con->createStatement();
    sql::ResultSet* res = stmt->executeQuery("SELECT * FROM users");

    while (res->next()) {
        User user;
        user.setUserID(res->getInt("user_id"));
        user.setFullname(res->getString("full_name"));
        user.setUserPassword(res->getString("master_password"));
        user.setSecurityQuestion(res->getString("security_question"));

        int userID = user.getuserID();
        Logins[userID] = user;
    }

    delete res;
    delete stmt;
    delete con;
}


// user login to the database
void  logIn(map<int, User>& logins)
{
    system("cls");
    int input_userID;
    string input_password;
    int attempt = 1;
    bool userExist = false;


    cout << "\033[1;36m----------------------------------------------------" << endl;
    cout << "                 ~ Log-In to Vault ~               " << endl;
    cout << "----------------------------------------------------\033[0m" << endl;


    cout << "\n\033[1;37mEnter your UserID: \033[0m";
    cin >> input_userID;

    for (auto user : logins)
    {
        if (user.first == input_userID)
        {
            userExist = true;
            break;

        }
    }

    if (userExist)
    {
        for (attempt = 0; attempt < 3; attempt++)
        {
            cout << "\n\033[1;37mEnter your master Password: \033[0m";
            input_password = getMaskedPassword();
            string hashedinput = sha256(input_password); //convert into hash
            for (auto user : logins)
            {

                if (user.second.getmasterPassword() == hashedinput && user.second.getuserID() == input_userID)
                {
                    cout << "\n\033[1;32mLogin Successful! \033[0m Enter to Open Vault ";
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                    cin.get(); // Wait for ENTER key
                    system("cls");
                    user.second.displayMenu();
                    return;
                }
            }

            cout << "\033[1;31mIncorrect Password  " << (attempt + 1) << "\033[0m\n";
        }

        cout << "\n\033[1;31mToo many failed attempts. \033[0m Try again later.\n";
    }

    else {
        cout << "\n\033[1;31mUser ID not found.\033[0m\n";
        return;
    }

}

// user registeration function ... user  user class & database manager class
void Register(map<int, User>& logins)
{
    system("cls");
    DatabaseManager db;
    User newUser;

    string inputname, inputpassword, inputsecurityQuestion;
    string hashedinput;

    // Registeration Menu
    {
        cout << "\033[1;36m\n----------------------------------------------------\n";
        cout << "                ~ Register to Vault ~                \n";
        cout << "----------------------------------------------------\033[0m\n";

        cout << "\n\033[1;37mYour Full Name: \033[0m";

        getline(cin, inputname);

        cout << "\n\033[1;37mYour Master Password: \033[0m";
        inputpassword = getMaskedPassword();

        hashedinput = sha256(inputpassword);

        cout << "\n\n\033[1;36m- Security Question - \033[0m\n";
        cout << "\nWhat is your favorite subject name? ";
        getline(cin, inputsecurityQuestion);


        if (inputname.empty()) {
            cout << "Error: Full name cannot be empty.\n";
            getline(cin, inputname);
        }

        if (inputpassword.empty()) {
            cout << "Error: Master password cannot be empty.\n";
            inputpassword = getMaskedPassword();
            hashedinput = sha256(inputpassword);
        }

        if (inputsecurityQuestion.empty()) {
            cout << "Error: Security question cannot be empty.\n";
            getline(cin, inputsecurityQuestion);
        }
    }
    int newuserid;
    if (db.getLastUserId() <= 0)
    {
        newuserid = 1;
    }
    else {
        newuserid = db.getLastUserId() + 1;  // get the latest userid from the database
    }

    newUser.setUserID(newuserid);
    newUser.setFullname(inputname);
    newUser.setUserPassword(hashedinput);
    newUser.setunhashedPassword(inputpassword);
    newUser.setSecurityQuestion(inputsecurityQuestion);

   

    db.insertUser(newuserid, inputname, hashedinput, inputsecurityQuestion);
    logins[newuserid] = newUser;

}

void forgot(map<int, User>& Logins)
{
    system("cls");
    int id;
    cout << "\033[1;36m\n------------------------------------------------------" << endl;
    cout << "                Forgot Password Page?            " << endl;
    cout << "------------------------------------------------------\033[0m" << endl;


    cout << "\n\033[1;37mEnter your userID :  \033[0m";
    cin >> id;
    cin.ignore();
    string ans;
    cout << "\n\033[1;37mWhat is your favorite subject ? \033[0m";
    getline(cin, ans);
    bool isfound = false;

    for (auto& user : Logins)
    {
        if ((user.second.getSecurityQuestion() == ans) && (user.second.getuserID() == id))
        {
            cout << "\n\033[1;32m Success! \033[0m ";
            DatabaseManager db;
            string security, name, password;
            cout << "\n\033[1;36m\n------------------------------------------------------\033[0m" << endl;
            cout << "\n\033[1;37mEnter new  Name (leave empty to keep current): \033[0m";
            getline(cin, name);
            cout << "\n\033[1;37mEnter new Password (leave empty to keep current): \033[0m";
            password = getMaskedPassword();
            string hashedinput = sha256(password);
            cout << "\n\033[1;37mEnter Security answer (leave empty to keep current): \033[0m";
            getline(cin, security);

            if (!name.empty())
            {
                user.second.setFullname(name);

            }
            if (!security.empty())
            {
                user.second.setSecurityQuestion(security);

            }

            if (!password.empty())
            {

                user.second.setUserPassword(hashedinput); // set the new hash for the user
            }

            isfound = true;
            // again assiging for original values
            name = user.second.getfullname();
            security = user.second.getSecurityQuestion();
            password = user.second.getmasterPassword();
            if (db.updateUser(id, name, password, security))
            {

                cout << "\n\033[1;32m Successfuly update.  \033[0m Click Enter & Login ";

                cin.ignore();
                return;

            }

        }

    }

    if (!isfound)
    {

        cout << "\033[1;31m Wrong Input! Try Register with a new One .\033[0m";
        cin.ignore();
        return;

    }


}
int main()
{

    map<int, User> Logins; // load user from the database to here 
    loadAllUsers(Logins);

    int choice;

    do
    {
        system("cls");
        cout << "\033[1;36m\n------------------------------------------------------" << endl;
        cout << "           Welcome to SecurePassword Vault            " << endl;
        cout << "------------------------------------------------------\033[0m\n" << endl;

        cout << "\033[1;37m1\033[0;37m - Register with a new Account" << endl;
        cout << "\033[1;37m2\033[0;37m - Login to Your Vault" << endl;
        cout << "\033[1;37m3\033[0;37m - Forgot Everything? " << endl;
        cout << "\033[1;37m0\033[0;37m - Exit" << endl;

        cout << "\n\033[1;36m------------------------------------------------------\033[0m";

        cout << "\nEnter your choice: ";
        cin >> choice;
        cin.ignore();

        switch (choice)
        {

        case 1:
        {
            Register(Logins);
        }
        break;

        case 2:
            logIn(Logins);
            break;

        case 3:
            loadAllUsers(Logins);
            forgot(Logins);
            break;

        default:
            cout << " " << endl;
        }

    } while (choice != 0);
}