#include "ldp_struct.h"
#include "mpls_timer_impl.h"
#include "mpls_mm_impl.h"

#include "thread.h"

struct mpls_timer {
    struct thread *timer;
    mpls_time_unit_enum unit;
    int duration;
    int type;
    void *extra;
    mpls_cfg_handle g;
    void (*callback) (mpls_timer_handle timer, void *extra, mpls_cfg_handle g);
    int active;
};

extern struct thread_master *master;

int mpls_timer(struct thread* thread) {
  mpls_timer_handle timer = THREAD_ARG(thread);

  timer->active = 0;
  if (timer->type == MPLS_TIMER_REOCCURRING) {
    timer->timer = thread_add_timer(master,mpls_timer,timer,timer->duration);
    timer->active = 1;
  }
  timer->callback(timer,timer->extra,timer->g);

  return 0;
}

mpls_timer_mgr_handle mpls_timer_open(mpls_instance_handle user_data)
{
  return 0xdeadbeef;
}

void mpls_timer_close(mpls_timer_mgr_handle handle)
{
}

mpls_timer_handle mpls_timer_create(mpls_timer_mgr_handle handle,
  mpls_time_unit_enum unit, int duration, void *extra, mpls_cfg_handle g,
  void (*callback) (mpls_timer_handle timer, void *extra, mpls_cfg_handle g))
{
  struct mpls_timer *timer;
  timer = mpls_malloc(sizeof(struct mpls_timer));
  timer->unit = unit;
  timer->duration = duration;
  timer->extra = extra;
  timer->g = g;
  timer->callback = callback;
  timer->active = 0;

  return timer;
}

mpls_return_enum mpls_timer_modify(mpls_timer_mgr_handle handle,
  mpls_timer_handle timer, int duration)
{
  if (!timer) {
    return MPLS_FAILURE;
  }
  timer->duration = duration;
  return MPLS_SUCCESS;
}

void mpls_timer_delete(mpls_timer_mgr_handle handle, mpls_timer_handle timer)
{
  if (timer) {
    mpls_free(timer);
  }
}

mpls_return_enum mpls_timer_start(mpls_timer_mgr_handle handle,
  mpls_timer_handle timer, mpls_timer_type_enum type)
{
  if (!timer) {
    return MPLS_FAILURE;
  }
  timer->type = type;
  timer->timer = thread_add_timer(master,mpls_timer,timer,timer->duration);
  timer->active = 1;
  return MPLS_SUCCESS;
}

void mpls_timer_stop(mpls_timer_mgr_handle handle, mpls_timer_handle timer)
{
  if (timer && timer->active) {
    thread_cancel(timer->timer);
    timer->timer = NULL;
  }
}
