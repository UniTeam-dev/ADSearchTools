import ADKit
import SwiftUI
import UniformTypeIdentifiers

struct ConnectView: View {
    @EnvironmentObject var model: AppModel
    @AppStorage("host") private var host = ""
    @AppStorage("port") private var port = 636
    @AppStorage("user") private var user = ""
    @AppStorage("remember") private var remember = true
    @State private var password = ""
    @State private var busy = false
    @State private var failure: Failure?
    @State private var advanced = false
    @State private var connectTask: Task<Void, Never>?
    @State private var triedAuto = false

    enum Failure {
        case ldap(UIError)
        case unreachable(UIError)
        case certificate(issuer: String, root: SecCertificate?)
        case nameMismatch(String)
        case trustFailed(String)
    }

    var body: some View {
        VStack(spacing: 14) {
            VStack(spacing: 6) {
                Image(systemName: "server.rack")
                    .font(.system(size: 26))
                    .foregroundStyle(Color.accentColor)
                    .frame(width: 56, height: 56)
                    .background(Color.accentColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 14))
                Text("Подключение к Active Directory").font(.title3.weight(.bold))
                Text("Контроллер домена и учётная запись администратора. Соединение только по LDAPS.")
                    .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }

            Form {
                TextField("Сервер", text: $host, prompt: Text("dc01.corp.local"))
                TextField("Порт", value: $port, format: .number.grouping(.never))
                TextField("Логин", text: $user, prompt: Text(verbatim: "user@corp.local или CORP\\user"))
                SecureField("Пароль", text: $password)
                Toggle("Запомнить пароль в Связке ключей", isOn: $remember)
            }
            .formStyle(.grouped)
            .scrollDisabled(true)
            .frame(height: 230)
            .disabled(busy)

            DisclosureGroup("Дополнительно", isExpanded: $advanced) {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("CA-сертификат")
                        Spacer()
                        Button("Выбрать файл и доверять…", action: pickCA)
                    }
                    Text("Нужен, если контроллер использует сертификат внутреннего CA, которому этот Mac ещё не доверяет. Сертификат добавится в Связку ключей, macOS попросит пароль от Mac. Форматы .cer, .crt, .pem.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                .padding(.top, 6)
            }

            if let failure { failureView(failure) }

            HStack {
                if busy {
                    ProgressView().controlSize(.small)
                    Text("Подключение к \(host):\(String(port))…").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                if busy { Button("Отменить") { connectTask?.cancel(); busy = false } }
                Button("Подключиться", action: connect)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(busy || host.isEmpty || user.isEmpty || password.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 460)
        .onAppear(perform: autoConnect)
    }

    @ViewBuilder
    private func failureView(_ f: Failure) -> some View {
        switch f {
        case .ldap(let e):
            ErrorBox(title: "Не удалось войти", message: e.message, technical: e.technical, symbol: "lock.fill", color: .red)
        case .unreachable(let e):
            ErrorBox(title: "Сервер \(host) недоступен", message: "Нет ответа на порту \(port). Проверьте VPN, имя сервера и порт.",
                     technical: e.technical, symbol: "wifi.exclamationmark")
        case .certificate(let issuer, let root):
            VStack(alignment: .leading, spacing: 8) {
                ErrorBox(title: "Сертификат сервера не доверенный",
                         message: "\(host) предъявил сертификат от «\(issuer)», которому этот Mac не доверяет. Добавьте корневой сертификат вашего CA в Связку ключей как доверенный.",
                         technical: "TLS · certificate verify failed", symbol: "checkmark.shield")
                HStack {
                    if let root {
                        Button("Доверять «\(TLSProbe.subjectName(root))»…") { trust(root) }
                    }
                    Button("Выбрать файл CA…", action: pickCA)
                }
            }
        case .nameMismatch(let name):
            ErrorBox(title: "Имя сервера не совпадает с сертификатом",
                     message: "Сертификат выдан для «\(name)», а подключение идёт к «\(host)». Укажите в поле «Сервер» полное имя контроллера из сертификата (FQDN), а не IP-адрес или короткое имя.",
                     technical: "TLS · hostname mismatch", symbol: "checkmark.shield")
        case .trustFailed(let msg):
            ErrorBox(title: "Не удалось добавить сертификат", message: msg)
        }
    }

    private func autoConnect() {
        guard !triedAuto, !model.suppressAutoConnect else { return }
        triedAuto = true
        guard remember, !host.isEmpty, !user.isEmpty, let saved = Keychain.password(for: account) else { return }
        password = saved
        connect()
    }

    private var account: String { "\(user)@\(host)" }

    private func connect() {
        failure = nil
        busy = true
        let cfg = ADConfig(host: host.trimmingCharacters(in: .whitespaces), port: port, user: user.trimmingCharacters(in: .whitespaces))
        let pw = password
        connectTask = Task {
            let d = ADDirectory(config: cfg, password: pw)
            do {
                let info = try await d.connect()
                guard !Task.isCancelled else { return }
                if remember { Keychain.save(pw, for: account) } else { Keychain.delete(account) }
                password = ""
                busy = false
                model.didConnect(d, info)
            } catch let e as LDAPError where e.isServerDown {
                let probe = await TLSProbe.run(host: cfg.host, port: cfg.port)
                guard !Task.isCancelled else { return }
                busy = false
                switch probe {
                case .untrusted(let issuer, let root): failure = .certificate(issuer: issuer, root: root); advanced = true
                case .nameMismatch(let name): failure = .nameMismatch(name)
                case .unreachable, .trusted: failure = .unreachable(UIError("", e))
                }
            } catch {
                guard !Task.isCancelled else { return }
                busy = false
                failure = .ldap(UIError("", error))
            }
        }
    }

    private func pickCA() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = ["cer", "crt", "pem", "der"].compactMap { UTType(filenameExtension: $0) }
        panel.message = "Выберите корневой сертификат CA вашего домена"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard let cert = TLSProbe.certificate(fromFile: url) else {
            failure = .trustFailed("Файл не похож на сертификат X.509 (.cer/.pem).")
            return
        }
        trust(cert)
    }

    private func trust(_ cert: SecCertificate) {
        do {
            try TLSProbe.trust(cert)
            failure = nil
            if !password.isEmpty { connect() }
        } catch {
            failure = .trustFailed("macOS не разрешила изменить доверие (\(error.localizedDescription)). Можно добавить сертификат вручную в «Связке ключей» и выставить «Всегда доверять».")
        }
    }
}
