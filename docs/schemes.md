# Проект PeerPipe

Приложения:
- Сервер
- Клиент *(docker)* + Suricata
- Клиент Desktop

## Схема 1. Сценарий использования
```mermaid
graph TD
    %% --- СТИЛИ ---
    classDef cloud fill:#f9f,stroke:#333,stroke-width:2px,color:#000,font-weight:bold;
    classDef desktop fill:#bbf,stroke:#005,stroke-width:2px,color:#000,font-weight:bold;
    classDef gateway fill:#f96,stroke:#333,stroke-width:4px,color:#000,font-weight:bold;
    classDef service fill:#dfd,stroke:#050,stroke-width:2px,color:#000,font-weight:bold;
    classDef app fill:#fff,stroke:#333,stroke-dasharray: 5 5,color:#000;

    %% --- УЗЛЫ ---
    subgraph Internet ["☁️ Глобальный Интернет / WAN"]
        direction TB
        Signaling["📡 Signaling Server<br/>(Discovery & Handshake)"]:::cloud
    end

    subgraph Remote ["🏠 Удаленный сотрудник (Home)"]
        direction TB
        IDE["🛠️ IDE / Браузер<br/>(Локальное приложение)"]:::app
        Desktop["💻 PeerPipe Desktop<br/>(Agent)"]:::desktop
        IDE ==>|"localhost"| Desktop
    end

    subgraph Office ["🏢 Офис / Кластер А"]
        direction TB
        GatewayA["🛡️ PeerPipe Gateway A<br/>(Docker + Suricata)"]:::gateway
        ServiceA["🗄️ База Данных (Legacy)"]:::service
    end

    subgraph CloudCluster ["☁️ Облако / Кластер Б"]
        direction TB
        GatewayB["🛡️ PeerPipe Gateway B<br/>(Docker + Suricata)"]:::gateway
        ServiceB["⚙️ Микросервис API #1"]:::service
        ServiceC["⚙️ Микросервис API #2"]:::service
    end

    %% --- СВЯЗИ ---
    %% Сигнализация
    Desktop -.- Signaling
    GatewayA -.- Signaling
    GatewayB -.- Signaling

    %% P2P Туннели (Данные)
    Desktop <==>|"P2P VPN (Сценарий: Работа из дома)"| GatewayA
    GatewayA <==>|"Inter-Cluster VPN"| GatewayB
    
    %% Локальные связи
    GatewayA --> ServiceA
    GatewayB --> ServiceB
    GatewayB --> ServiceC

    %% --- СТИЛИ ЛИНИЙ ---
    linkStyle 4,5 stroke-width:4px,fill:none,stroke:green,color:lightyellow;
```

---

## Схема 2. Изоляция сетей

```mermaid
graph LR
    %% --- СТИЛИ ---
    classDef internet fill:#fff,stroke:#333,stroke-dasharray: 5 5,color:#000;
    classDef gateway fill:#f96,stroke:#333,stroke-width:4px,color:#000,font-weight:bold;
    classDef secure fill:#dfd,stroke:#0a0,stroke-width:2px,color:#000,font-weight:bold;
    
    subgraph World ["🌍 Внешний мир (Интернет)"]
        Hacker["👹 Хакер"]
    end

    subgraph Cluster1 ["📦 Кластер 1 (Офис)"]
        subgraph PubNet1 ["Network: bridge"]
            GW1["🛡️ PeerPipe Gateway 1"]:::gateway
        end
        subgraph PrivNet1 ["🔒 Network: internal (Isol)"]
            DB1[("🛢️ SQL Database")]:::secure
        end
    end

    subgraph Cluster2 ["📦 Кластер 2 (Облако)"]
        subgraph PubNet2 ["Network: bridge"]
            GW2["🛡️ PeerPipe Gateway 2"]:::gateway
        end
        subgraph PrivNet2 ["🔒 Network: internal (Isol)"]
            API2["⚙️ Backend API"]:::secure
        end
    end

    %% СВЯЗИ
    %% Туннель между шлюзами
    GW1 <==>|"Encrypted P2P Tunnel"| GW2
    
    %% Хакер не может пробиться
    Hacker -.->|"❌ Blocked"| GW1
    Hacker -.->|"❌ Blocked"| GW2

    %% Внутри кластера 1
    GW1 <-->|"Чистый трафик"| DB1
    
    %% Внутри кластера 2
    GW2 <-->|"Чистый трафик"| API2

    %% Демонстрация изоляции (Air Gap)
    DB1 -.->|"❌ Нет маршрута"| World
    API2 -.->|"❌ Нет маршрута"| World

    linkStyle 0 stroke:green,stroke-width:4px;
    linkStyle 5,6 stroke:red,stroke-width:2px,stroke-dasharray: 3 3,color:red;
```

---
## Схема 3.1 Процесс обработки соединения PeerPipe Gateway, чистое соединение

```mermaid
sequenceDiagram
    autonumber
    %% Настройка участников
    participant Tunnel as 🌐 P2P Туннель (UDP)
    participant GW as 🛡️ PeerPipe Gateway
    participant Iface as ➿ Docker Interface (Eth0)
    participant IDS as 👁️ Suricata (Sidecar)
    participant Service as 🎯 Целевой Сервис

    Note over Tunnel,GW: Входящий пакет из Интернета
    Tunnel->>GW: Зашифрованные данные (DTLS)
    
    rect rgba(206, 144, 30, 0.32)
    Note over GW,Service: Внутри защищенного периметра
    GW->>GW: Расшифровка (AES+ГОСТ)
    
    GW->>Iface: Отправка в локальную сеть
    
    par Инспекция и Доставка
        Iface->>Service: Передача данных (TCP Request)
        Iface->>IDS: Зеркалирование трафика (Sniffing)
    end
    end

    Note over IDS: Анализ сигнатур (ET Open)...
    

    rect rgba(0, 138, 37, 0.32)
    Service-->>Iface: Ответ (Data)
    Iface->>GW: Ответ
    GW->>Tunnel: Шифрование и отправка
    end
```

---
## Схема 3.2 Процесс обработки соединения PeerPipe Gateway, опасное соединение

```mermaid
sequenceDiagram
    autonumber
    %% Настройка участников
    participant Tunnel as 🌐 P2P Туннель (UDP)
    participant GW as 🛡️ PeerPipe Gateway
    participant Iface as ➿ Docker Interface (Eth0)
    participant IDS as 👁️ Suricata (Sidecar)
    participant Service as 🎯 Целевой Сервис

    Note over Tunnel,GW: Входящий пакет из Интернета
    Tunnel->>GW: Зашифрованные данные (DTLS)
    
    rect rgba(206, 144, 30, 0.32)
    Note over GW,Service: Внутри защищенного периметра
    GW->>GW: Расшифровка (AES+ГОСТ)
    
    GW->>Iface: Отправка в локальную сеть
    
    par Инспекция и Доставка
        Iface->>Service: Передача данных (TCP Request)
        Iface->>IDS: Зеркалирование трафика (Sniffing)
    end
    end

    Note over IDS: Анализ сигнатур (ET Open)...
    
    rect rgba(206, 62, 30, 0.32)
    IDS-->>GW: 🚨 ALERT: Exploit Detected (JSON)
    Note over GW: IPS Реакция
    GW->>Tunnel: ❌ Разрыв P2P соединения
    GW->>Service: ❌ Закрытие сокета
    end
```

---
## Схема 4. Установление P2P-соединения

```mermaid
sequenceDiagram
    autonumber
    %% Настройки
    participant Alice as 💻 Alice (Initiator)
    participant Server as 📡 Server (Signaling)
    participant Bob as 🖥️ Bob (Listener)

    Note over Alice,Bob: Фаза 1: Знакомство через Сервер (WebSocket)
    
    Alice->>Server: 1. JOIN_ROOM (RoomID)
    Bob->>Server: 2. JOIN_ROOM (RoomID)
    Server-->>Alice: 3. NEW_PEER (Bob)
    
    Note over Alice: Создание SDP Offer
    Alice->>Server: 4. SEND_SDP (Type: Offer)
    Server->>Bob: 5. FORWARD_SDP (Offer)
    
    Note over Bob: Применение Offer -> Создание Answer
    Bob->>Server: 6. SEND_SDP (Type: Answer)
    Server->>Alice: 7. FORWARD_SDP (Answer)
    
    Note over Alice,Bob: Фаза 2: Пробивка NAT (Trickle ICE)
    
    par Обмен кандидатами
        Alice->>Bob: ICE Candidates (через Server)
        Bob->>Alice: ICE Candidates (через Server)
    end
    
    Note over Alice,Bob: Фаза 3: Прямое соединение (P2P)
    
    rect rgba(200, 255, 200, 0.4)
        Note over Alice,Bob: ✅ DTLS Handshake & Data Channel Open
        Alice->>Bob: P2P Трафик - Зашифрован
        Bob->>Alice: P2P Трафик - Зашифрован
    end
    
    Note over Alice,Bob: Сервер больше не нужен для данных
```

---
## Схема 5. Инкапсуляция данных

```mermaid
graph TD
    %% Стили
    classDef payload fill:#f9f,stroke:#333,stroke-width:2px,color:#000,font-weight:bold;
    classDef header fill:#bbf,stroke:#333,stroke-width:2px,color:#000;
    classDef transport fill:#dfd,stroke:#333,stroke-width:2px,color:#000;
    classDef physical fill:#eee,stroke:#333,stroke-width:2px,color:#000;

    subgraph PacketStructure ["📦 Структура пакета"]
        direction TB
        
        subgraph AppLayer ["Layer 7: Application + ГОСТ"]
            Compression["Флаг сжатия (1 байт)"]:::payload
            Data["Полезная нагрузка<br/>(Сжатый HTTP/SQL/RDP)"]:::payload
        end

        subgraph SecurityLayer ["Layer 6: Session"]
            SCTP["SCTP Stream (Mux/Demux)"]:::header
            DTLS["DTLS (Шифрование AES)"]:::header
        end

        subgraph TransportLayer ["Layer 4: Transport"]
            UDP["UDP Header (Порты)"]:::transport
        end

        subgraph NetworkLayer ["Layer 3: Network"]
            IP["IP Header (Адреса)"]:::physical
        end
    end

    %% Связи (Вложенность)
    Compression --- Data
    Data --> SCTP
    SCTP --> DTLS
    DTLS --> UDP
    UDP --> IP

    %% Пояснения (В КАВЫЧКАХ)
    Note1["Код PeerPipe<br/>(Python)"] -.-> AppLayer
    Note2["Стек WebRTC (aiortc)"] -.-> SecurityLayer
    Note3["ОС / Железо"] -.-> TransportLayer
```
