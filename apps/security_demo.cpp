#include "telemetry/console_colors.hpp"
#include "telemetry/protocol_agents.hpp"
#include <chrono>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

using namespace telemetry;

namespace {

constexpr auto kStepDelay = std::chrono::milliseconds(450);

void pause() { std::this_thread::sleep_for(kStepDelay); }

void title(const std::string& text) {
    std::cout << "\n" << ansi::yellow << "=== " << text << " ===" << ansi::reset << "\n";
    pause();
}

void step(int n, int total, const std::string& text) {
    std::cout << "[" << n << "/" << total << "] " << text << "\n";
    pause();
}

void info(const std::string& text) {
    std::cout << "      " << text << "\n";
    pause();
}

void outcome(bool ok, const std::string& text) {
    std::cout << (ok ? ansi::green : ansi::red) << (ok ? "PASSED: " : "FAILED: ") << text << ansi::reset << "\n";
}

std::string shortHex(const Bytes& b, size_t n = 10) {
    std::string full = toHex(b);
    return full.substr(0, n * 2) + "...";
}

// Виділяє кольором конкретне значення, на яке варто звернути увагу (число,
// що порівнюється між кроками) - решта рядка лишається звичайного кольору.
std::string hl(const std::string& s) { return std::string(ansi::cyan) + ansi::bold + s + ansi::reset; }

// std::to_string(float) прописує повну (нечитабельну) точність, наприклад "231.399994"
// замість "231.4" - цей форматер друкує числа так само чисто, як звичайний std::cout.
std::string fmtF(float v) {
    std::ostringstream os;
    os << v;
    return os.str();
}

struct HandshakedPair {
    DeviceAgent device;
    GatewayAgent gateway;
};

HandshakedPair freshHandshakedPair(const std::string& deviceId = "esp32-node-01") {
    EccIdentity identity;
    Bytes pubKey = identity.publicKeyUncompressed();

    DeviceAgent device(deviceId, std::move(identity));
    GatewayAgent gateway;
    gateway.registerTrustedDevice(deviceId, pubKey);

    HelloMessage deviceHello = device.buildHello();
    HelloMessage gatewayHello = gateway.acceptHello(deviceHello);
    device.completeHandshake(gatewayHello);

    return HandshakedPair{std::move(device), std::move(gateway)};
}

TelemetryPacket samplePacket() {
    TelemetryPacket p;
    p.unixTimestampMs = 1'726'000'000'000ULL;
    p.voltageV = 231.4f;
    p.currentA = 2.87f;
    p.powerW = 664.1f;
    p.temperatureC = 33.2f;
    return p;
}

void scenarioHappyPath() {
    title("1. Штатний обмін телеметрією");
    step(1, 7, "Пристрій генерує ДОВГОТРИВАЛУ ECDSA-ідентичність (P-256) - вона не міняється між сеансами зв'язку.");
    EccIdentity identity;
    Bytes pubKey = identity.publicKeyUncompressed();
    info("публічний ключ ідентичності: " + shortHex(pubKey));
    DeviceAgent device("esp32-node-01", std::move(identity));
    GatewayAgent gateway;
    gateway.registerTrustedDevice("esp32-node-01", pubKey);

    step(2, 7, "Хендшейк: додатково генерується ОДНОРАЗОВА пара ефемерних ECDH-ключів (лише для цього сеансу).");
    HelloMessage deviceHello = device.buildHello();
    info("ефемерний ключ пристрою (інший за ключ ідентичності вище!): " + shortHex(deviceHello.ephemeralPublicKey));
    HelloMessage gatewayHello = gateway.acceptHello(deviceHello);
    info("ефемерний ключ шлюзу у відповідь: " + shortHex(gatewayHello.ephemeralPublicKey));
    device.completeHandshake(gatewayHello);
    info("з цих двох ефемерних ключів обчислено спільний секрет -> сесійний AES-256 ключ (HKDF-SHA256)");

    TelemetryPacket p = samplePacket();
    step(3, 7, "Пристрій має пакет із сирими показаннями датчика:");
    std::string sentValues = "U=" + fmtF(p.voltageV) + "V  I=" + fmtF(p.currentA) + "A  P=" + fmtF(p.powerW) +
                              "W  T=" + fmtF(p.temperatureC) + "C";
    info(hl(sentValues) + "  <- запам'ятайте ці числа");

    step(4, 7, "Пристрій шифрує пакет сесійним ключем (AES-256-GCM) і підписує весь конверт ключем ідентичності (ECDSA-SHA256).");
    TelemetryEnvelope msg = device.protect(p);
    info("seq=" + hl(std::to_string(msg.sequenceNumber)) + "  nonce=" + shortHex(msg.nonce) + "  tag=" + shortHex(msg.tag));
    info("шифротекст: " + std::to_string(msg.ciphertext.size()) + " байт;  підпис: " +
         std::to_string(msg.signature.size()) + " байт");

    step(5, 7, "Конверт іде мережею до шлюзу (тут - виклик у пам'яті, у реальності - TCP/HTTP).");

    step(6, 7, "Шлюз, у такому порядку: перевіряє ECDSA-підпис -> перевіряє номер послідовності -> розшифровує AES-GCM.");
    TelemetryPacket recovered = gateway.unprotect(msg);
    std::string recoveredValues = "U=" + fmtF(recovered.voltageV) + "V  I=" + fmtF(recovered.currentA) + "A  P=" +
                                   fmtF(recovered.powerW) + "W  T=" + fmtF(recovered.temperatureC) + "C";
    info("розшифровано: " + hl(recoveredValues) + "  <- порівняйте з кроком 3");

    step(7, 7, "Звіряємо розшифровані дані з тим, що відправив пристрій (рядок вище з рядком на кроці 3).");
    bool ok = recovered.voltageV == p.voltageV && recovered.currentA == p.currentA && recovered.powerW == p.powerW &&
              recovered.temperatureC == p.temperatureC;
    outcome(ok, "значення повністю збіглися - шлюз прийняв пакет, конфіденційність і цілісність збережено");
}

void scenarioForwardSecrecy() {
    title("2. Пряма секретність (forward secrecy)");
    std::string deviceId = "esp32-node-01";
    EccIdentity identity;
    Bytes pubKey = identity.publicKeyUncompressed();

    info("(нижче два РІЗНІ типи значень: ефемерний ключ - публічна точка кривої (65 байт, для обміну),");
    info(" сесійний ключ - симетричний AES-ключ (32 байти), вирахуваний з цього обміну - їх не треба порівнювати між собою)");

    step(1, 5, "Хендшейк #1: пристрій і шлюз генерують по одноразовій парі ефемерних ECDH-ключів.");
    EphemeralKeyPair deviceEph1;
    EphemeralKeyPair gatewayEph1;
    info("ефемерний ключ пристрою: " + shortHex(deviceEph1.publicKeyUncompressed()));
    info("ефемерний ключ шлюзу:    " + shortHex(gatewayEph1.publicKeyUncompressed()));
    Bytes transcript1 = handshakeTranscript(deviceId, deviceEph1.publicKeyUncompressed(), gatewayEph1.publicKeyUncompressed());
    SessionKey key1 = deviceEph1.deriveSessionKey(gatewayEph1.publicKeyUncompressed(), transcript1, handshakeHkdfInfo());
    info("=> сесійний AES-ключ хендшейку #1: " + hl(shortHex(Bytes(key1.begin(), key1.end()))));

    step(2, 5, "Хендшейк #2: та сама пара пристрій-шлюз, нова розмова - ефемерні ключі генеруються заново.");
    EphemeralKeyPair deviceEph2;
    EphemeralKeyPair gatewayEph2;
    info("ефемерний ключ пристрою: " + shortHex(deviceEph2.publicKeyUncompressed()) + " (інший за хендшейк #1)");
    info("ефемерний ключ шлюзу:    " + shortHex(gatewayEph2.publicKeyUncompressed()) + " (інший за хендшейк #1)");
    Bytes transcript2 = handshakeTranscript(deviceId, deviceEph2.publicKeyUncompressed(), gatewayEph2.publicKeyUncompressed());
    SessionKey key2 = deviceEph2.deriveSessionKey(gatewayEph2.publicKeyUncompressed(), transcript2, handshakeHkdfInfo());
    info("=> сесійний AES-ключ хендшейку #2: " + hl(shortHex(Bytes(key2.begin(), key2.end()))) + "  <- порівняйте з хендшейком #1");

    step(3, 5, "Для порівняння: довготривала ECDSA-ідентичність пристрою в обох хендшейках лишається ТА САМА.");
    info("публічний ключ ідентичності (незмінний в обох сесіях): " + shortHex(pubKey));

    step(4, 5, "А ось ефемерні приватні ключі одразу забуваються після хендшейку (ніде не зберігаються).");
    info("суть forward secrecy: навіть якщо зловмисник пізніше вкраде довготривалий ключ ідентичності, він не зможе " +
         std::string("відновити ефемерні ключі й розшифрувати вже завершені сесії заднім числом"));

    step(5, 5, "Порівнюємо саме два сесійні AES-ключі (хендшейк #1 проти хендшейку #2) побайтово.");
    bool different = !std::equal(key1.begin(), key1.end(), key2.begin());
    outcome(different, "сесійні ключі різні -> компрометація ключа сесії #1 не розкриває дані сесії #2 (forward secrecy)");
}

void scenarioTamperRejected() {
    title("3. Підміна шифротексту в польоті (MITM)");
    auto pair = freshHandshakedPair();
    TelemetryEnvelope msg = pair.device.protect(samplePacket());
    step(1, 4, "Пристрій надіслав справжній, підписаний конверт.");
    info("ciphertext[0..3] до підміни: " + toHex(Bytes(msg.ciphertext.begin(), msg.ciphertext.begin() + 4)));
    info("підпис обчислено над усім конвертом, включно з цим шифротекстом: " + shortHex(msg.signature));

    step(2, 4, "Зловмисник перехоплює пакет 'у польоті' й змінює лише перший байт шифротексту.");
    uint8_t before = msg.ciphertext[0];
    msg.ciphertext[0] ^= 0xFF;
    info("ciphertext[0]: " + hl("0x" + toHex({before})) + " -> " + hl("0x" + toHex({msg.ciphertext[0]})) +
         " (підпис лишили як є)");

    step(3, 4, "Підмінений пакет надсилається шлюзу під виглядом справжнього.");
    try {
        pair.gateway.unprotect(msg);
        outcome(false, "шлюз помилково прийняв підмінені дані");
    } catch (const SecurityException& e) {
        step(4, 4, "Шлюз перевіряє ECDSA-підпис першим (він охоплює й шифротекст) - тож підпис уже не збігається.");
        info("до перевірки AES-GCM тегу справа навіть не доходить - зайва робота над завідомо підробленими даними не витрачається");
        outcome(true, std::string("відхилено: ") + e.what());
    }
}

void scenarioExactReplayRejected() {
    title("4. Повторне відтворення - точний дублікат (replay)");
    auto pair = freshHandshakedPair();
    TelemetryEnvelope msg = pair.device.protect(samplePacket());
    step(1, 4, "Пристрій надсилає пакет із номером послідовності seq=" + std::to_string(msg.sequenceNumber) + ".");
    pair.gateway.unprotect(msg);
    info("шлюз прийняв, внутрішньо запам'ятав: останній прийнятий номер для 'esp32-node-01' = " +
         hl(std::to_string(msg.sequenceNumber)));

    step(2, 4, "Зловмисник не зміг би підробити новий пакет (немає приватного ключа), тож просто ЗАПИСАВ старий байт-у-байт.");
    step(3, 4, "І надсилає той самий, повністю справжній (валідний підпис і тег) пакет ще раз, без жодних змін.");
    try {
        pair.gateway.unprotect(msg);
        outcome(false, "шлюз помилково прийняв повтор");
    } catch (const SecurityException& e) {
        step(4, 4, "Криптографія тут безсила (пакет справжній!) - рятує лише лічильник послідовності.");
        outcome(true, std::string("відхилено: ") + e.what());
    }
}

void scenarioOlderSequenceRejected() {
    title("5. Повторне відтворення - старий (не щойно повторений) номер");
    auto pair = freshHandshakedPair();
    TelemetryEnvelope msg3;
    for (int i = 0; i < 10; ++i) {
        TelemetryEnvelope m = pair.device.protect(samplePacket());
        if (i == 2) msg3 = m;
        pair.gateway.unprotect(m);
    }
    step(1, 3, "Шлюз уже прийняв пакети #1..#10 послідовно, внутрішній лічильник 'останній прийнятий' = " + hl("10") + ".");
    info("(msg3, збережений на кроці #3, мав seq=" + hl(std::to_string(msg3.sequenceNumber)) + ")");
    step(2, 3, "Зловмисник надсилає збережений раніше пакет #3 - не точний дублікат #10, а просто старіший номер.");
    try {
        pair.gateway.unprotect(msg3);
        outcome(false, "шлюз помилково прийняв застарілий пакет");
    } catch (const SecurityException& e) {
        step(3, 3, "Перевірка в GatewayAgent::unprotect(): sequenceNumber має бути СТРОГО більшим за останній прийнятий.");
        outcome(true, std::string("відхилено: ") + e.what());
    }
}

void scenarioGapAccepted() {
    title("6. Пропуск номерів у послідовності (втрата пакетів мережею)");
    auto pair = freshHandshakedPair();
    step(1, 4, "Пристрій готує й підписує п'ять окремих пакетів: #1, #2, #3, #4, #5.");
    std::vector<TelemetryEnvelope> msgs;
    for (int i = 0; i < 5; ++i) msgs.push_back(pair.device.protect(samplePacket()));
    info("кожен підписаний окремо своїм справжнім ключем, кожен має власний унікальний nonce");

    step(2, 4, "У дорозі (TCP/Wi-Fi/локальна мережа) губляться пакети #2, #3, #4 - звичайна ситуація на практиці.");
    step(3, 4, "До шлюзу фізично доходять лише #1 і #5.");
    pair.gateway.unprotect(msgs[0]);
    info("шлюз отримав #1 -> прийнято, внутрішній лічильник 'останній прийнятий' = " + hl("1"));

    step(4, 4, "Тепер приходить #5 (номер зростає з 1 одразу до 5, а не на +1).");
    try {
        TelemetryPacket recovered = pair.gateway.unprotect(msgs[4]);
        info("умова прийняття - sequenceNumber(" + hl("5") + ") > lastSequence(" + hl("1") +
             "), а не sequenceNumber == lastSequence+1");
        outcome(true, "пакет #5 прийнято, хоча #2-#4 ніколи не приходили - протокол не вимагає суцільної послідовності, лише зростання");
        (void)recovered;
    } catch (const SecurityException& e) {
        outcome(false, std::string("несподівано відхилено: ") + e.what());
    }
}

void scenarioForgedSignatureRejected() {
    title("7. Підроблений підпис (чужий приватний ключ)");
    EccIdentity victimIdentity;
    Bytes victimKey = victimIdentity.publicKeyUncompressed();
    DeviceAgent device("victim-device", std::move(victimIdentity));
    GatewayAgent gateway;
    gateway.registerTrustedDevice("victim-device", victimKey);
    HelloMessage deviceHello = device.buildHello();
    HelloMessage gatewayHello = gateway.acceptHello(deviceHello);
    device.completeHandshake(gatewayHello);

    step(1, 6, "У шлюза зареєстрований конкретний публічний ключ 'victim-device' (виданий при провіжнінгу).");
    info("зареєстрований ключ: " + hl(shortHex(victimKey)));

    TelemetryEnvelope msg = device.protect(samplePacket());
    step(2, 6, "Справжній пристрій підписав би пакет саме цим ключем - ось як виглядав би легітимний підпис:");
    info("справжній підпис 'victim-device': " + hl(shortHex(msg.signature)));

    step(3, 6, "Зловмисник генерує власну, зовсім іншу пару ключів (не має доступу до приватного ключа victim-device).");
    EccIdentity attacker;
    Bytes attackerKey = attacker.publicKeyUncompressed();
    info("ключ зловмисника: " + hl(shortHex(attackerKey)) + "  <- порівняйте із зареєстрованим ключем на кроці 1");

    step(4, 6, "Зловмисник підписує той самий пакет СВОЇМ приватним ключем замість справжнього.");
    msg.signature = attacker.sign(msg.signedTranscript());
    info("підроблений підпис (чужим ключем): " + hl(shortHex(msg.signature)) + "  <- порівняйте зі справжнім підписом на кроці 2");

    step(5, 6, "Підроблений пакет надсилається під виглядом 'victim-device' (deviceId у полі не змінено).");
    try {
        gateway.unprotect(msg);
        outcome(false, "шлюз помилково прийняв підроблений підпис");
    } catch (const SecurityException& e) {
        step(6, 6, "EccIdentity::verify() перевіряє підпис саме проти ключа, зареєстрованого за 'victim-device' -> не збігається.");
        outcome(true, std::string("відхилено: ") + e.what());
    }
}

void scenarioUnknownDeviceRejected() {
    title("8. Невідомий пристрій (не зареєстрований у шлюзі)");
    GatewayAgent gateway;
    Bytes key01 = EccIdentity().publicKeyUncompressed();
    Bytes key02 = EccIdentity().publicKeyUncompressed();
    gateway.registerTrustedDevice("esp32-node-01", key01);
    gateway.registerTrustedDevice("esp32-node-02", key02);
    step(1, 4, "У реєстрі шлюзу рівно два довірені записи:");
    info("'esp32-node-01' -> " + hl(shortHex(key01)));
    info("'esp32-node-02' -> " + hl(shortHex(key02)));

    EccIdentity identity;
    Bytes impostorKey = identity.publicKeyUncompressed();
    DeviceAgent impostor("nobody-registered-me", std::move(identity));
    step(2, 4, "Третій пристрій ('nobody-registered-me') має власну справжню, коректно згенеровану ідентичність.");
    info("ключ 'nobody-registered-me': " + hl(shortHex(impostorKey)) + "  <- валідний ключ, але відсутній у списку вище");

    step(3, 4, "Він намагається почати хендшейк, надсилаючи Hello.");
    HelloMessage hello = impostor.buildHello();
    info("Hello(deviceId='nobody-registered-me', ефемерний ключ=" + shortHex(hello.ephemeralPublicKey) + ") - усе коректно сформовано");
    try {
        gateway.acceptHello(hello);
        outcome(false, "шлюз помилково прийняв хендшейк");
    } catch (const SecurityException& e) {
        step(4, 4, "GatewayAgent::isTrusted() шукає лише сам deviceId у реєстрі (двох записах вище) - навіть не дивлячись на ключ.");
        info("справа в тому, ЩО ключ належить справжньому власнику - а не в тому, чи він 'правильно виглядає';");
        info("'nobody-registered-me' просто відсутній у списку -> відхилено ще до будь-якої криптографії");
        outcome(true, std::string("відхилено: ") + e.what());
    }
}

void scenarioMultiDeviceIsolation() {
    title("9. Ізоляція кількох пристроїв одночасно");
    step(1, 4, "Реєструємо два незалежні пристрої на одному шлюзі, кожен зі своєю окремою ECDSA-ідентичністю.");
    EccIdentity identityA;
    Bytes pubKeyA = identityA.publicKeyUncompressed();
    DeviceAgent deviceA("device-A", std::move(identityA));
    GatewayAgent gateway;
    gateway.registerTrustedDevice("device-A", pubKeyA);
    HelloMessage helloA = deviceA.buildHello();
    HelloMessage gwHelloA = gateway.acceptHello(helloA);
    deviceA.completeHandshake(gwHelloA);
    info("device-A: ключ ідентичності " + hl(shortHex(pubKeyA)));

    EccIdentity identityB;
    Bytes pubKeyB = identityB.publicKeyUncompressed();
    DeviceAgent deviceB("device-B", std::move(identityB));
    gateway.registerTrustedDevice("device-B", pubKeyB);
    HelloMessage helloB = deviceB.buildHello();
    HelloMessage gwHelloB = gateway.acceptHello(helloB);
    deviceB.completeHandshake(gwHelloB);
    info("device-B: ключ ідентичності " + hl(shortHex(pubKeyB)) + "  <- порівняйте з device-A вище, зовсім інший");

    step(2, 4, "device-A надсилає 15 повідомлень поспіль, усі приймаються.");
    for (int i = 0; i < 15; ++i) {
        TelemetryEnvelope m = deviceA.protect(samplePacket());
        gateway.unprotect(m);
    }
    info("device-A: внутрішній лічильник шлюзу 'останній прийнятий' = " + hl("15"));

    step(3, 4, "device-B, який ще жодного разу не надсилав телеметрію, готує своє ПЕРШЕ повідомлення.");
    TelemetryEnvelope mB = deviceB.protect(samplePacket());
    info("device-B: seq=" + hl(std::to_string(mB.sequenceNumber)) +
         "  <- власний лічильник з 0, не залежить від device-A (15 прийнятих вище)");

    step(4, 4, "Шлюз обробляє пакет device-B через ту саму сесію (тільки-но зареєстровану для нього).");
    try {
        TelemetryPacket recoveredB = gateway.unprotect(mB);
        outcome(true, "device-B: пакет #1 прийнято - лічильник device-A (15 прийнятих) жодним чином не вплинув на device-B");
        (void)recoveredB;
    } catch (const SecurityException& e) {
        outcome(false, std::string("несподівано відхилено: ") + e.what());
    }
}

void printMenu() {
    std::cout << "\n"
              << ansi::yellow << "Оберіть сценарій для живої демонстрації:" << ansi::reset << "\n"
              << "  1 - Штатний обмін телеметрією\n"
              << "  2 - Пряма секретність (forward secrecy)\n"
              << "  3 - Підміна шифротексту в польоті (MITM)\n"
              << "  4 - Replay: точний дублікат пакета\n"
              << "  5 - Replay: старий (не щойно повторений) номер\n"
              << "  6 - Пропуск номерів (втрата пакетів мережею)\n"
              << "  7 - Підроблений підпис (чужий ключ)\n"
              << "  8 - Невідомий (не зареєстрований) пристрій\n"
              << "  9 - Ізоляція кількох пристроїв одночасно\n"
              << "  0 - Виконати всі сценарії підряд\n"
              << "  q - Вихід\n"
              << "> ";
}

void runScenario(int choice) {
    switch (choice) {
        case 1: scenarioHappyPath(); break;
        case 2: scenarioForwardSecrecy(); break;
        case 3: scenarioTamperRejected(); break;
        case 4: scenarioExactReplayRejected(); break;
        case 5: scenarioOlderSequenceRejected(); break;
        case 6: scenarioGapAccepted(); break;
        case 7: scenarioForgedSignatureRejected(); break;
        case 8: scenarioUnknownDeviceRejected(); break;
        case 9: scenarioMultiDeviceIsolation(); break;
        default: std::cout << ansi::red << "Невідомий вибір.\n" << ansi::reset; break;
    }
}

}

int main() {
    std::cout << std::unitbuf;
    ansi::enable();
    std::cout << ansi::yellow << "Secure Telemetry - жива демонстрація безпеки протоколу\n"
              << "ECDH (P-256) + AES-256-GCM + ECDSA-SHA256" << ansi::reset << "\n";

    std::string line;
    while (true) {
        printMenu();
        if (!std::getline(std::cin, line)) break;
        if (line == "q" || line == "Q") break;
        if (line == "0") {
            for (int i = 1; i <= 9; ++i) runScenario(i);
            continue;
        }
        try {
            int choice = std::stoi(line);
            runScenario(choice);
        } catch (const std::exception&) {
            std::cout << ansi::red << "Введіть число від 0 до 9 або 'q'.\n" << ansi::reset;
        }
    }
    std::cout << "Завершено.\n";
    return 0;
}
