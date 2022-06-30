package JavaCardMain.utils;

import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Database {

    public Connection ConnectDB() {
        try {
            Class.forName("com.mysql.jdbc.Driver");
            Connection con = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/javacard", "root", "123456");
            System.out.println("connect db success");
            return con;
        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }

    public int countNumber() {
        int count = 0;
        try {
            Connection con = this.ConnectDB();
            Statement stmt = con.createStatement();
            ResultSet rs = stmt.executeQuery("select count(*) from user");
            while (rs.next()) {
                count = rs.getInt(1);
            }
            con.close();
            return count;
        } catch (Exception e) {
            System.out.println(e);
            return count;
        }
    }

    public User getUserById(int id) throws SQLException {
        User user = null;
        Connection con = this.ConnectDB();
        Statement stmt = con.createStatement();
        ResultSet rs = stmt.executeQuery("select * from user where id=" + id);
        while (rs.next()) {
            user = new User(rs.getInt(1), rs.getString(2));
        }
        con.close();
        return user;
    }

    public void save(User user) throws SQLException {
        Connection con = this.ConnectDB();
        Statement stmt = con.createStatement();
        String sql = "insert into user (public_key) values (" + "'" + user.getPublicKey() + "'" + ")";
        System.out.println(sql);
        int result = stmt.executeUpdate(sql);
        System.out.println(result);
        con.close();
    }

    public static void main(String args[]) {
        try {
            Database db = new Database();
            User user = db.getUserById(1);
            db.save(user);
        } catch (SQLException ex) {
            Logger.getLogger(Database.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
