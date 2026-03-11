#include "ForensicImageExtractor/workers/TaskRunner.h"

namespace fie::workers {

TaskRunner::TaskRunner(QObject *parent) : QObject(parent) { m_pool.setMaxThreadCount(4); }

void TaskRunner::enqueue(std::function<void()> fn) { m_pool.start(new LambdaTask(std::move(fn))); }

} // namespace fie::workers
