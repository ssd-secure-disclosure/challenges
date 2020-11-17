#include <thread>
#include <chrono>
#include <random>
#ifdef _WIN
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif
static const size_t COLS = 0x20;
static const size_t PRIVATE_KEY_ROWS = 3;
char EXPORT private_key[PRIVATE_KEY_ROWS][COLS] = {
  0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0,
  0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0,
  0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1
};
static const size_t MIN_KEY_LENGTH = 3 * COLS;
size_t EXPORT private_key_length = MIN_KEY_LENGTH; //+ 1 + ((unsigned int)std::rand()) % COLS;
size_t EXPORT number_of_rows = 0x10;
static const size_t WAIT_FOR = 800;
static const size_t XOR_KEY = 0xDF098B52;
EXPORT size_t encrypt(size_t num)
{
  std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR));
  return num ^ XOR_KEY;
}
EXPORT size_t decrypt(size_t num)
{
  std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR));
  return num ^ XOR_KEY;
}
