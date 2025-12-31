// RIVER WEBSITE/backend/src/audit/audit.queue.ts


/**
 * 
 *
 * BullMQ based queue to persist audit events with retries and dead-letter queue (DLQ).
 * Requires Redis and BullMQ.
 *
 * npm install bullmq ioredis
 */

import { Queue, Worker, QueueScheduler, JobsOptions } from "bullmq";
import IORedis from "ioredis";
import { persistAudit } from "./audit.persistence.ts";

const connection = new IORedis(process.env.REDIS_URL || "redis://localhost:6379");
const auditQueue = new Queue("auditQueue", { connection });
const auditScheduler = new QueueScheduler("auditQueue", { connection });

// Worker to process audit persistence with retry logic
const worker = new Worker("auditQueue", async job => {
  const data = job.data;
  // call persistAudit which writes to DB & emits logs
  await persistAudit(data);
}, { connection, concurrency: 5 });

// Optional: worker to move failed jobs to dead-letter queue for inspection
worker.on("failed", async (job, err) => {
  console.error("Audit job failed:", job.id, err?.message);
  // After consumer retries exhausted, BullMQ will move to failed state; you can move it to a DLQ queue
});

export async function enqueueAudit(payload: any) {
  const opts: JobsOptions = { attempts: 5, backoff: { type: "exponential", delay: 1000 } };
  await auditQueue.add("persist", payload, opts);
}

export { auditQueue, worker };