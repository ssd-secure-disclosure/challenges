#include <iostream>
#include <thread>
#include <chrono>
#ifdef _WIN
#define IMPORT extern __declspec(dllimport)
#else
#define IMPORT extern
#endif
IMPORT size_t encrypt(size_t num);
IMPORT  size_t decrypt(size_t num);
IMPORT const char private_key[];
IMPORT const size_t private_key_length;
IMPORT const size_t number_of_rows;
class Algo
{
public:
  static const size_t ROWS = 0x20;
  static const size_t COLS = 0x20;
  char table[ROWS][COLS] = { {0} };
  char * password;
  union
  {
    struct
    {
      size_t unused : 3;
      size_t init : 1;
    } s1;
    size_t number_of_rows : 5;
  } u1 = {};
  struct
  {
    size_t row : 7;
    int i : 7;
    char exponent[COLS];
    size_t x;
  } expo_data = {};
  static void StoreNumber(char * row, size_t num, bool enc = true)
  {
    if (enc)
      num = encrypt(num);
    for (int i = COLS - 1; i >= 0; i--)
    {
      row[i] = num % 2;
      num = num / 2;
    }
  }
  static void RetrieveNumber(char * row, size_t& num)
  {
    num = 0;
    for (int i = 0; i < COLS; i++)
    {
      num = num * 2 + row[i];
    }
    num = decrypt(num);
  }
  void Calculate_next()
  {
    expo_data.x = expo_data.x * expo_data.x;
    if (expo_data.exponent[expo_data.i++] == 1)
    {
      size_t num = 0;
      RetrieveNumber(table[expo_data.row], num);
      expo_data.x = expo_data.x * num;
    }
  }
  void End_calc()
  {
    StoreNumber(table[expo_data.row], std::hash<size_t>()(expo_data.x));
    u1.s1.init = 0;
    u1.s1.init = false;
  }
  void InitializeExp(size_t row1, size_t row2)
  {
    std::copy(table[row2], table[row2] + COLS, expo_data.exponent);
    expo_data.i = 0;
    while (expo_data.exponent[expo_data.i] == 0 && expo_data.i < COLS)
    {
      ++expo_data.i;
    }
    expo_data.x = 1;
    expo_data.row = row1;
  }
  void Multiply(size_t row1, size_t row2, size_t row3)
  {
    size_t num1 = 0, num2 = 0, num3 = 0;
    RetrieveNumber(table[row1], num1);
    RetrieveNumber(table[row2], num2);
    num3 = num1 * num2;
    StoreNumber(table[row3], num3);
  }
  void Add(size_t row1, size_t row2, size_t row3)
  {
    size_t num1 = 0, num2 = 0, num3 = 0;
    RetrieveNumber(table[row1], num1);
    RetrieveNumber(table[row2], num2);
    num3 = num1 + num2;
    StoreNumber(table[row3], num3);
  }
  void Sub(size_t row1, size_t row2, size_t row3)
  {
    size_t num1 = 0, num2 = 0, num3 = 0;
    RetrieveNumber(table[row1], num1);
    RetrieveNumber(table[row2], num2);
    num3 = num1 - num2;
    StoreNumber(table[row3], num3);
  }
  void Divide(size_t row1, size_t row2, size_t row3)
  {
    size_t num1 = 0, num2 = 0, num3 = 0;
    RetrieveNumber(table[row1], num1);
    RetrieveNumber(table[row2], num2);
    if (num2 == 0)
    {
      return;
    }
    num3 = num1 / num2;
    StoreNumber(table[row3], num3);
  }
  bool ValidateRowIndex(size_t row)
  {
    return (row < u1.number_of_rows);
  }
  void Encryption()
  {
    if (expo_data.i > COLS - 1)
    {
      End_calc();
      return;
    }
    char op = 0;
    std::cout << "Continue Encryption? (y/n)" << std::endl;
    std::cin >> op;
    switch (op)
    {
    case 'y':
    case 'Y':
      Calculate_next();
      break;
    case 'n':
    case 'N':
      End_calc();
      break;
    }
    return;
  }
  void CopyTable(char t1[ROWS][COLS], char t2[ROWS][COLS])
  {
    for (unsigned int i = 0; i < ROWS; i++)
    {
      size_t num = 0;
      RetrieveNumber(t1[i], num);
      StoreNumber(t2[i], num, false);
    }
  }
  void PrintTable()
  {
#ifdef DEBUG
    char t[ROWS][COLS] = { 0 };
    CopyTable(table, t);
    size_t col_size = 0x20;
    std::cout << " ";
    for (int i = 0; i < col_size; i++)
    {
      std::cout << "--";
    }
    std::cout << std::endl;
    for (int i = 0; i < u1.number_of_rows; i++)
    {
      std::cout << "<|";
      for (int j = 0; j < ROWS; j++)
      {
        std::cout << (char)(('0' + t[i][j])) << "|";
      }
      std::cout << ">" << std::endl;
    }
    std::cout << " ";
    for (int i = 0; i < col_size; i++)
    {
      std::cout << "--";
    }
    std::cout << std::endl;
#endif
  }
  void Init()
  {
#ifdef _DEBUG
    for (unsigned int i = 0; i < ROWS; i++)
    {
      StoreNumber(table[i], 0);
    }
#endif
  }
  void MainLoop()
  {
    bool done = false;
    Init();
    password = table[number_of_rows + 2];
    std::copy(&private_key[0], &private_key[0] + private_key_length, password);
    password[private_key_length - 1] |= 1;
    u1.number_of_rows = number_of_rows;
    while (!done)
    {
      if (u1.s1.init)
      {
        Encryption();
        continue;
      }
      size_t op = 0;
      std::cout << "Please choose your option:" << std::endl;
      std::cout << "0. Store Number" << std::endl;
      std::cout << "1. Get Number" << std::endl;
      std::cout << "2. Add" << std::endl;
      std::cout << "3. Subtract" << std::endl;
      std::cout << "4. Multiply" << std::endl;
      std::cout << "5. Divide" << std::endl;
      std::cout << "6. Private Key Encryption" << std::endl;
      std::cout << "7. Binary Representation" << std::endl;
      std::cout << "8. Exit" << std::endl;
      std::cin >> op;
      if (!std::cin)
      {
        done = true;
        break;
      }
      switch (op)
      {
      case 0:
      {
        size_t row = 0;
        size_t num = 0;
        std::cout << "Enter row and number" << std::endl;
        std::cin >> row >> num;
        if (!std::cin)
        {
          done = true;
          break;
        }
        if (!ValidateRowIndex(row))
        {
          std::cout << "Row number is out of range" << std::endl;
          break;
        }
        StoreNumber(table[row], num);
        break;
      }
      case 1:
      {
        size_t row = 0;
        size_t num = 0;
        std::cout << "Enter row" << std::endl;
        std::cin >> row;
        if (!std::cin)
        {
          done = true;
          break;
        }
        if (!ValidateRowIndex(row))
        {
          std::cout << "Row number is out of range" << std::endl;
          break;
        }
        RetrieveNumber(table[row], num);
        std::cout << "Result is " << num << std::endl;
        break;
      }
      case 2:
      {
        size_t row1 = 0, row2 = 0, row3 = 0;
        std::cout << "Enter row of arg1, row of arg2 and row of result" << std::endl;
        std::cin >> row1 >> row2 >> row3;
        if (!std::cin)
        {
          done = true;
          break;
        }
        if (!(ValidateRowIndex(row1) && ValidateRowIndex(row2) && ValidateRowIndex(row3)))
        {
          std::cout << "Row number is out of range" << std::endl;
          break;
        }
        Add(row1, row2, row3);
        break;
      }
      case 3:
      {
        size_t row1 = 0, row2 = 0, row3 = 0;
        std::cout << "Enter row of arg1, row of arg2 and row of result" << std::endl;
        std::cin >> row1 >> row2 >> row3;
        if (!std::cin)
        {
          done = true;
          break;
        }
        if (!(ValidateRowIndex(row1) && ValidateRowIndex(row2) && ValidateRowIndex(row3)))
        {
          std::cout << "Row number is out of range" << std::endl;
          break;
        }
        Sub(row1, row2, row3);
        break;
      }
      case 4:
      {
        size_t row1 = 0, row2 = 0, row3 = 0;
        std::cout << "Enter row of arg1, row of arg2 and row of result" << std::endl;
        std::cin >> row1 >> row2 >> row3;
        if (!std::cin)
        {
          done = true;
          break;
        }
        if (!(ValidateRowIndex(row1) && ValidateRowIndex(row2) && ValidateRowIndex(row3)))
        {
          std::cout << "Row number is out of range" << std::endl;
          break;
        }
        Multiply(row1, row2, row3);
        break;
      }
      case 5:
      {
        size_t row1 = 0, row2 = 0, row3 = 0;
        std::cout << "Enter row of arg1, row of arg2 and row of result" << std::endl;
        std::cin >> row1 >> row2 >> row3;
        if (!std::cin)
        {
          done = true;
          break;
        }
        if (!(ValidateRowIndex(row1) && ValidateRowIndex(row2) && ValidateRowIndex(row3)))
        {
          std::cout << "Row number is out of range" << std::endl;
          break;
        }
        Divide(row1, row2, row3);
        break;
      }
      case 6:
      {
        size_t row1 = 0, row2 = 0;
        u1.s1.init = 1;
        std::cout << "Enter row of message, row of key" << std::endl;
        std::cin >> row1 >> row2;
        if (!std::cin)
        {
          done = true;
          break;
        }
        if (!(ValidateRowIndex(row1) && ValidateRowIndex(row2)))
        {
          u1.s1.init = 0;
          std::cout << "Row number is out of range" << std::endl;
          break;
        }
        InitializeExp(row1, row2);
        break;
      }
      case 7:
      {
        PrintTable();
        break;
      }
      case 8:
      {
        done = true;
        break;
      }
      default:
      {
        std::cout << "Unknown option." << std::endl;
        break;
      }
      }
    }
  }
};
Algo a;
int main()
{
  a.MainLoop();
  return 0;
}
