package com.synthlab.synthlab_api.Entities;

import java.util.Date;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "app_user")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String nombre;
    private String apellido_paterno;
    private String apellido_materno;
    private String correo;
    private String password;
    private Date fecha_nacimiento;
    private Date created_at;
    private String pathAvatar;

    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getNombre() {
        return nombre;
    }
    public void setNombre(String nombre) {
        this.nombre = nombre;
    }
    public String getApellidoPaterno() {
        return apellido_paterno;
    }
    public void setApellidoPaterno(String apellido_paterno) {
        this.apellido_paterno = apellido_paterno;
    }
    public String getApellidoMaterno() {
        return apellido_materno;
    }
    public void setApellidoMaterno(String apellido_materno) {
        this.apellido_materno = apellido_materno;
    }
    public String getCorreo() {
        return correo;
    }
    public void setCorreo(String correo) {
        this.correo = correo;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public Date getFechaNacimiento() {
        return fecha_nacimiento;
    }
    public void setFechaNacimiento(Date fecha_nacimiento) {
        this.fecha_nacimiento = fecha_nacimiento;
    }
    public Date getCreatedAt() {
        return created_at;
    }
    public void setCreatedAt(Date created_at) {
        this.created_at = created_at;
    }
    public String getPathAvatar() {
        return pathAvatar;
    }
    public void setPathAvatar(String path_avatar) {
        this.pathAvatar = path_avatar;
    }

    
}
