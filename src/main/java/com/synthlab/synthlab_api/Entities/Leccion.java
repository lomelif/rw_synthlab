    package com.synthlab.synthlab_api.Entities;

    import jakarta.persistence.*;
    import java.util.List;
    
    import com.fasterxml.jackson.annotation.JsonManagedReference;
    
    @Entity
    @Table(name = "leccion")
    public class Leccion {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;
    
        private String titulo;
    
        @OneToMany(mappedBy = "leccion", fetch = FetchType.LAZY)
        @JsonManagedReference
        private List<LeccionContenido> contenidos;

        public Long getId() {
            return id;
        }

        public void setId(Long id) {
            this.id = id;
        }

        public String getTitulo() {
            return titulo;
        }

        public void setTitulo(String titulo) {
            this.titulo = titulo;
        }

        public List<LeccionContenido> getContenidos() {
            return contenidos;
        }

        public void setContenidos(List<LeccionContenido> contenidos) {
            this.contenidos = contenidos;
        }

        
    }
    
