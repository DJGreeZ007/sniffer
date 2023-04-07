#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h> // подключение библиотеки Windows Sockets 2 для сетевого программирования
#include <Ws2tcpip.h> // дополнительная библиотека для работы с сетевыми протоколами
#include <iostream> // стандартный ввод/вывод в консоли
#include <fstream> // чтение/запись в файл
#include <string>

#pragma comment(lib, "ws2_32.lib") // подключение библиотеки ws2_32.lib

void analyzeIpPacket(char* buffer, int size, std::ofstream& file) // функция анализа IP-пакета
{
    char* ip_header = buffer; // указатель на начало IP-заголовка
    int ip_header_length = (*ip_header & 0x0F) * 4; // длина IP-заголовка
    int ip_version = (*ip_header & 0xF0) >> 4; // версия IP-протокола
    int ip_total_length = ntohs(*(unsigned short*)(ip_header + 2)); // общая длина IP-пакета
    int ip_protocol = *(ip_header + 9); // протокол следующего уровня
    std::string src_ip = inet_ntoa(*(in_addr*)(ip_header + 12)); // исходный IP-адрес
    std::string dst_ip = inet_ntoa(*(in_addr*)(ip_header + 16)); // адрес получателя

    if (ip_protocol == IPPROTO_TCP) // если протокол - TCP
    {
        char* tcp_header = ip_header + ip_header_length; // указатель на начало TCP-заголовка
        int tcp_header_length = (*(tcp_header + 12) >> 4) * 4; // длина TCP-заголовка
        int src_port = ntohs(*(unsigned short*)tcp_header); // исходный порт
        int dst_port = ntohs(*(unsigned short*)(tcp_header + 2)); // порт получателя
        int tcp_seq = ntohl(*(unsigned int*)(tcp_header + 4)); // номер последовательности TCP-сегмента
        int tcp_ack = ntohl(*(unsigned int*)(tcp_header + 8)); // номер подтверждения TCP-сегмента
        std::string log_msg = "TCP: " + src_ip + ":" + std::to_string(src_port) + " -> "
            + dst_ip + ":" + std::to_string(dst_port) + " Seq=" + std::to_string(tcp_seq) +
            " Ack=" + std::to_string(tcp_ack); // строка для записи в лог-файл
        file << log_msg << std::endl; // запись в лог-файл
        std::cout << log_msg << std::endl;
    }
    else if (ip_protocol == IPPROTO_UDP) // если протокол - UDP
    {
        char* udp_header = ip_header + ip_header_length; // указатель на начало UDP-заголовка
        int src_port = ntohs(*(unsigned short*)udp_header); // исходный порт
        int dst_port = ntohs(*(unsigned short*)(udp_header + 2)); // порт получателя
        int udp_length = ntohs(*(unsigned short*)(udp_header + 4)); // длина UDP-пакета
        std::string log_msg = "UDP: " + src_ip + ":" + std::to_string(src_port) + " -> "
            + dst_ip + ":" + std::to_string(dst_port) + " Length="
            + std::to_string(udp_length); // строка для записи в лог-файл
        file << log_msg << std::endl; // запись в лог-файл
        std::cout << log_msg << std::endl;
    }
    else if (ip_protocol == IPPROTO_ICMP) // если протокол - ICMP, в задании нет этого протокола, но пусть будет
    {
        std::string log_msg = "ICMP: " + src_ip + " -> " + dst_ip; // строка для записи в лог-файл
        file << log_msg << std::endl; // запись в лог-файл
        std::cout << log_msg << std::endl;
    }
    else // для всех остальных протоколов
    {
        std::string log_msg = "IP: " + src_ip + " -> " + dst_ip; // строка для записи в лог-файл
        file << log_msg << std::endl; // запись в лог-файл
        std::cout << log_msg << std::endl;
    }
}

int main(int argc, char* argv[]) // главная функция
{
    setlocale(LC_ALL, "Russian");
    if (argc != 3) // проверка правильности ввода IP-адреса и пути до лог-файла
    {
        std::cerr << "Usage: sniffer.exe IP_ADDRESS LOG_FILE_PATH" << std::endl; // вывод сообщения об ошибке
        return -1; // завершение работы программы
    }

    std::string ip_address = argv[1]; // IP-адрес
    std::string log_file_path = argv[2]; // путь до лог-файла
    std::ofstream logfile(log_file_path); // создание лог-файла
    if (!logfile.is_open()) // проверка на успешное создание лог-файла
    {
        std::cerr << "Error: Unable to open log file: " << log_file_path << std::endl; // вывод сообщения об ошибке
        return -1; // завершение работы программы
    }

    WSADATA wsaData; // информация о версии Windows Sockets
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) // проверка на успешное подключение к Windows Sockets
    {
        std::cerr << "Error: Unable to start Windows Sockets" << std::endl; // вывод сообщения об ошибке
        return -1; // завершение работы программы
    }
    SOCKET sniffer_socket = INVALID_SOCKET;
    sniffer_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP); // создание сокета для перехвата пакетов
    if (sniffer_socket == INVALID_SOCKET) // проверка на успешное создание сокета
    {
        std::cerr << "Error: Unable to create a socket" << std::endl; // вывод сообщения об ошибке
        return -1; // завершение работы программы
    }

    sockaddr_in socket_address; // структура для задания адреса сокета
    socket_address.sin_family = AF_INET; // тип адреса - IPv4
    socket_address.sin_addr.s_addr = inet_addr(ip_address.c_str()); // IP-адрес, который мы хотим слушать
    socket_address.sin_port = 0; // порт = 0, говорим системе слушать все порты по этому адресу
    if (bind(sniffer_socket, (SOCKADDR*)&socket_address, sizeof(socket_address)) == SOCKET_ERROR) // привязка сокета к определенному IP-адресу
    {
        std::cerr << "Error: Unable to bind the socket" << std::endl; // вывод сообщения об ошибке
        return -1; // завершение работы программы
    }

    char recv_buf[65536]; // буфер для приема пакетов
    int recv_size = 0; // размер полученного пакета
    int sockAddrSize = sizeof(socket_address);
    while (true) // бесконечный цикл для приема пакетов
    {
        memset(recv_buf, 0, 65536); // очистка буфера
        //recv_size = recv(sniffer_socket, recv_buf, 65536, 0); // прием пакета через сокет
        recv_size = recvfrom(sniffer_socket, recv_buf, 65536, 0, (SOCKADDR*)&socket_address, &sockAddrSize);
        if (recv_size > 0) // проверка на успешный прием пакета
        {
            analyzeIpPacket(recv_buf, recv_size, logfile); // анализ полученного пакета
        }
    }
    logfile.close();
    closesocket(sniffer_socket); // закрытие сокета
    WSACleanup(); // выключение Windows Sockets

    return 0; // завершение работы программы
}