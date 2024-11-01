package by.che.authorization.controllers;

import by.che.authorization.model.UserEntity;
import by.che.authorization.service.ServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private ServiceImpl service;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserEntity user, Model model) {
        String registrationResult = service.registerUser(user);

        switch (registrationResult) {
            case "Имя пользователя занято":
                return ResponseEntity
                        .badRequest()
                        .body("Имя пользователя занято");

            case "Неверный формат пароля":
                return ResponseEntity
                        .badRequest()
                        .body("Пароль должен содержать хотя бы одну заглавную, строчную букву и специальный символ");

            case "Поля не могут быть пустыми":
                return ResponseEntity
                        .badRequest()
                        .body("Пожалуйста, заполните все поля");

            default:
                return ResponseEntity
                        .ok()
                        .body("Пользователь успешно зарегистрирован");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestParam("login") String userName, @RequestParam("password") String password) {
        return ResponseEntity.ok(service.login(userName, password));
    }

    @GetMapping("/all")
    public ResponseEntity<?> getAll() {
        return ResponseEntity.ok(service.getAll());
    }
}
