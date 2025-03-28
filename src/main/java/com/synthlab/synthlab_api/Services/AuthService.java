package com.synthlab.synthlab_api.Services;

import com.synthlab.synthlab_api.Entities.User;
import com.synthlab.synthlab_api.Repositories.UserRepository;
import com.synthlab.synthlab_api.Security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public String register(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "Usuario registrado con éxito";
    }

    public String login(String correo, String password) {
        Optional<User> user = userRepository.findByCorreo(correo);
        if (user.isPresent() && passwordEncoder.matches(password, user.get().getPassword())) {
            return jwtUtil.generateToken(user.get().getCorreo());
        }
        return null;
    }
}
