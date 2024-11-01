package by.che.authorization.security;

import by.che.authorization.service.CustomUserDetailService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/*
    Аутентификация и авторизация:
    Настраивает механизмы аутентификации и правила доступа для приложения.
    Это позволяет контролировать, кто имеет доступ к определенным ресурсам
    и защищает приложение от несанкционированного доступа.

    Управление JWT:
    Позволяет генерировать и использовать JWT для аутентификации,
    что является стандартным подходом для RESTful API.
    JWT позволяет передавать информацию о пользователе между
    клиентом и сервером в защищенном формате.

    Шифрование паролей:
    Обеспечивает безопасное хранение паролей с использованием современного алгоритма шифрования.
 */

@Configuration
public class SecurityConfig {
    @Value("${keyStore.path}")
    private String keyStorePath;
    @Value("${keyStore.password}")
    private String keyStorePassword;

    private final CustomUserDetailService customUserDetailService;

    public SecurityConfig(CustomUserDetailService customUserDetailService) {
        this.customUserDetailService = customUserDetailService;
    }

/*
    Цепочка фильтров безопасности:
    Конфигурация цепочки фильтров безопасности, которая управляет обработкой запросов.
    Отключение CSRF-защиты может быть оправдано в REST API, так как используется
    аутентификация по токену, а не сессиям.
*/
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/register", "/api/login").permitAll()
                        .requestMatchers("/api/all").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .formLogin(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

/*
    Определяет, как будет шифроваться пароль пользователя. В данном случае используется
    BCryptPasswordEncoder, который применяет алгоритм bcrypt для безопасного хранения паролей
*/
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

/*
    Определяет, как пользователи будут аутентифицированы.
    Возвращает экземпляр AuthenticationManager для управления процессом аутентификации.
*/
    @Bean
    public AuthenticationManager authenticationManager (AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return  authenticationConfiguration.getAuthenticationManager();
    }

/*
    Генерация JWT:
    Создание экземпляра JwtEncoder для генерации JWT.
    Используются RSA-ключи, загружаемые из хранилища ключей, что обеспечивает
    безопасность токенов.
*/
    @Bean
    public JwtEncoder jwtEncoder() throws UnrecoverableKeyException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        RSAKey rsaKey = loadRSAKey();
        JWKSource<SecurityContext> jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(rsaKey));
        return new NimbusJwtEncoder(jwkSource);
    }

/*
    Метод, отвечающий за загрузку RSA-ключей из хранилища ключей.
    Извлекаются как открытый, так и закрытый ключи для подписи и верификации JWT.
    Ключи хранятся в формате JKS (Java KeyStore), который защищает их от несанкционированного доступа.
*/
    private RSAKey loadRSAKey() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new ClassPathResource(keyStorePath).getInputStream(), keyStorePassword.toCharArray());
        RSAPublicKey pubKey = (RSAPublicKey) keyStore.getCertificate("data-center").getPublicKey();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey("data-center", keyStorePassword.toCharArray());
        return new RSAKey.Builder(pubKey).privateKey(privateKey).keyID("data-center").build();
    }
}
