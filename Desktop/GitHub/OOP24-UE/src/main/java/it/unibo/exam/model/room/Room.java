package main.java.it.unibo.exam.model.room;

import java.awt.Color;
import java.util.List;
import main.java.it.unibo.exam.model.entity.Door;

public class Room {
    private Color backgroundColor;
    private List<Door> doors;
    
    public Room(Color backgroundColor, List<Door> doors) {
        this.backgroundColor = backgroundColor;
        this.doors = doors;
    }
    
    public List<Door> getDoors() {
        return doors;
    }
    
    public Color getBackgroundColor() {
        return backgroundColor;
    }
    
    public void setBackgroundColor(Color color) {
        this.backgroundColor = color;
    }
}