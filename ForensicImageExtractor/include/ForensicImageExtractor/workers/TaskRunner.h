#pragma once

#include <QObject>
#include <QRunnable>
#include <QThreadPool>
#include <functional>

namespace fie::workers {

class LambdaTask : public QRunnable {
public:
  explicit LambdaTask(std::function<void()> fn) : m_fn(std::move(fn)) {}
  void run() override { m_fn(); }

private:
  std::function<void()> m_fn;
};

class TaskRunner : public QObject {
  Q_OBJECT
public:
  explicit TaskRunner(QObject *parent = nullptr);
  void enqueue(std::function<void()> fn);

private:
  QThreadPool m_pool;
};

} // namespace fie::workers
