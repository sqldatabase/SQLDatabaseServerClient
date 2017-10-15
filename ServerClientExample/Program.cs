using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SQLDatabase.Net.Server.Client;

namespace ServerClientExample
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Running OpenCloseConnection Example ");
            OpenCloseConnection();

            Console.WriteLine("Running CreateDropDatabase Example ");
            CreateDropDatabase();

            Console.WriteLine("Running CreateDropUser Example ");
            CreateDropUser();

            Console.WriteLine("Running CreateTable Example ");
            CreateTable();

            Console.WriteLine("Running ORMClient Example ");
            ORMClient();

            Console.WriteLine("Running CacheServer Example ");
            CacheServer();

            Console.WriteLine("press enter key to exit.");
            Console.ReadLine();
        }


        static void OpenCloseConnection()
        {
            SQLDatabaseConnection cnn = new SQLDatabaseConnection();
            cnn.Server = "192.168.0.10";
            cnn.Port = 5000;
            cnn.Username = "sysadm";
            cnn.Password = "system";
            cnn.Open();
            Console.WriteLine(cnn.State);
            cnn.Close();
            cnn.Dispose();
            Console.WriteLine("OpenCloseConnection() Completed");
        }

        static void CreateDropDatabase()
        {
            SQLDatabaseConnection cnn = new SQLDatabaseConnection();
            cnn.Server = "192.168.0.10";
            cnn.Port = 5000;
            cnn.Username = "sysadm";
            cnn.Password = "system";
            cnn.Open();
            if (cnn.State == ConnectionState.Open)
            {
                SQLDatabaseCommand cmd = new SQLDatabaseCommand(cnn);
                SQLDatabaseUtility u = new SQLDatabaseUtility();
                u.Command = cmd;
                u.CreateDatabase("TestDatabase");
                u.DropDatabase("TestDatabase");
            }
            cnn.Close();
            cnn.Dispose();
            Console.WriteLine("CreateDropDatabase() Completed");
        }


        static void CreateDropUser()
        {
            SQLDatabaseConnection cnn = new SQLDatabaseConnection();
            cnn.Server = "192.168.0.10";
            cnn.Port = 5000;
            cnn.Username = "sysadm";
            cnn.Password = "system";
            cnn.Open();
            if (cnn.State == ConnectionState.Open)
            {
                SQLDatabaseCommand cmd = new SQLDatabaseCommand(cnn);
                SQLDatabaseUtility u = new SQLDatabaseUtility();
                u.Command = cmd;
                u.CreateUser("testuser", "testpass");
                //u.Grant("TestDatabase", "testuser");                
                u.DropUser("testuser");                
            }            
            cnn.Close();
            cnn.Dispose();
            Console.WriteLine("CreateDropUser() Completed");
        }

        static void CreateTable()
        {
            SQLDatabaseConnection cnn = new SQLDatabaseConnection();
            cnn.Server = "192.168.0.10";
            cnn.Port = 5000;
            cnn.Username = "sysadm";
            cnn.Password = "system";
            cnn.Open();
            if (cnn.State == ConnectionState.Open)
            {
                SQLDatabaseResultSet[] rs;
                SQLDatabaseCommand cmd = new SQLDatabaseCommand(cnn);
                SQLDatabaseUtility u = new SQLDatabaseUtility();
                u.Command = cmd;
                u.CreateDatabase("testdb");
                cnn.DatabaseName = "testdb";
                cnn.MultipleActiveResultSets = true;

                cmd.CommandText = "Create table if not exists testtable (id integer, textvalue text);";
                rs = cmd.ExecuteNonQuery();

                cmd.CommandText = "Insert Into testtable VALUES (1, 'example 1');";
                cmd.ExecuteNonQuery();
                
                cmd.CommandText = "SELECT * FROM testtable;";
                rs = cmd.ExecuteReader();

                foreach (SQLDatabaseResultSet drs in rs) { 
                    if (drs != null)
                    {
                        if (!string.IsNullOrWhiteSpace(drs.ErrorMessage))
                        {
                            Console.WriteLine(drs.ErrorMessage);
                        }
                        else
                        {
                            for (int r = 0; r < drs.RowCount; r++)
                            {
                                for (int c = 0; c < drs.ColumnCount; c++)
                                {
                                    Console.Write(drs.Columns[c] + "(" + drs.DataTypes[c] + ")");
                                    Console.Write("\t");
                                }

                                Console.WriteLine("");

                                for (int c = 0; c < drs.ColumnCount; c++)
                                {
                                    Console.Write(drs.Rows[r][c]);
                                    Console.Write("\t");
                                }

                            }

                            Console.WriteLine("");
                        }

                    }
                }
                cmd.CommandText = "DROP TABLE testtable;";
                cmd.ExecuteNonQuery();
                u.DropDatabase("testdb");
            }
            cnn.Close();
            cnn.Dispose();
            Console.WriteLine("CreateTable() Completed");
        }

        static void ORMClient()
        {
            SQLDatabaseConnection cnn = new SQLDatabaseConnection();
            cnn.Server = "192.168.0.10";
            cnn.Port = 5000;
            cnn.Username = "sysadm";
            cnn.Password = "system";
            cnn.Open();
            if (cnn.State == ConnectionState.Open)
            {

                SQLDatabaseCommand cmd = new SQLDatabaseCommand(cnn);
                SQLDatabaseUtility u = new SQLDatabaseUtility();
                u.Command = cmd;
                u.CreateDatabase("ormtestdb");
                cnn.DatabaseName = "ormtestdb";

                ApplicationUser e = new ApplicationUser();
                SQLDatabaseOrmClient<ApplicationUser> orm = new SQLDatabaseOrmClient<ApplicationUser>();
                orm.Connection = cnn;
                orm.CreateTable(e);

                e.Id = 1;
                e.Name = "SQLUser";
                e.Job = "SQL Developer";

                orm.Add(e); // add

                ApplicationUser user = orm.GetById(1); //get one by id
                
                Console.WriteLine("Id \t {0} ", user.Id);
                Console.WriteLine("Name \t {0} ", user.Name);
                Console.WriteLine("Job \t {0} ", user.Job);

                user.Job = "New Job";
                orm.Update(user);
                
                // Get all
                IList<ApplicationUser> userList = orm.GetAll();

                //Filter example;
                SQLDatabaseOrmClient<ApplicationUser>.Filter<ApplicationUser> f = new SQLDatabaseOrmClient<ApplicationUser>.Filter<ApplicationUser>();
                f.Add(x => x.Id, 1);//get user with id of 1

                //methods for order by and contains including limiting number of returned rows.
                //f.Add(x => x.Name, "SQLUser");
                //f.OrderBy(x => x.Name, "DESC");
                //f.Contains(x => x.Name, "u");
                //f.Limit(10, 10);
                

                //to find use following
                IList<ApplicationUser> foundUsers = orm.Find(f).ToList();

                //to remove use following
                orm.Remove(f);

                //remove or drop entire entity
                orm.DropTable(user);
                u.DropDatabase("ormtestdb");
            }
            cnn.Close();
            cnn.Dispose();
            Console.WriteLine("ORMClient() Completed");
        }

        static void CacheServer()
        {
            SQLDatabaseConnection cnn = new SQLDatabaseConnection();
            cnn.Server = "192.168.0.10";
            cnn.Port = 5000;
            cnn.Username = "sysadm";
            cnn.Password = "system";
            cnn.Open();
            
            if (cnn.State == ConnectionState.Open)
            {
                SQLDatabaseCacheServer cs = new SQLDatabaseCacheServer();
                cs.Connection = cnn;

                // In Cache server collections are automatically created if one does not exist.
                //Add remove raw bytes with Cache Id of 101 and collection name System.String
                //if trying to exchange strings or data with other programing languages use raw
                cs.AddRaw("System.String", Encoding.UTF8.GetBytes("Example Text for Cache Server"), "101");
                string c101 = Encoding.UTF8.GetString((byte[])cs.Get("System.String", "101")).ToString();
                cs.Remove("System.String", "101");

                cs.Add<string>("Example Text for Cache Server", "101");
                c101 = cs.Get<string>("101");
                cs.Remove<string>("101");


                ApplicationUser u = new ApplicationUser();
                u.Id = 1;
                u.Name = "SQLUser";
                u.Job = "SQL Developer";

                string id = cs.Add<ApplicationUser>(u);
                ApplicationUser user = cs.Get<ApplicationUser>(id);
                Console.WriteLine("Id \t {0} ", user.Id);
                Console.WriteLine("Name \t {0} ", user.Name);
                Console.WriteLine("Job \t {0} ", user.Job);

                List<string> collectionList = cs.CollectionList();
                foreach (string collectionName in collectionList)
                    Console.WriteLine("Collection : {0}",collectionName);

                
                cs.DropCollection("System.String");
                cs.DropCollection<ApplicationUser>();

            }

            cnn.Close();
            cnn.Dispose();
            Console.WriteLine("CacheServer() Completed");
        }
    }


    [Serializable()]
    public class ApplicationUser
    {
        [DBColumn(AutoIncrement = true, PrimaryKey = true)]
        public long Id { get; set; }
        [DBColumn]
        public string Name { get; set; }
        [DBColumn]
        public string Job { get; set; }
    }
}
