# Brand Guard page-probe worker: runbook

Built 2026-10-07 for plan steps 7.1 and 7.2, under the approved design (`BRAND_GUARD_STAGE7_EGRESS_DESIGN.md`, option A). **Everything is off by default.** Nothing probes a suspect host until you do all of the steps below.

## What runs where
- **API (your app host):** queues probe jobs (live look-alikes only), hands them out, receives results, cleans and analyses them. It never contacts a suspect host.
- **Worker (a separate machine):** `backend/probe_worker/worker.py`. Pulls one job, reads the home page, the favicon and the TLS certificate, posts the result back. Holds no database access and no customer data, only the signing key.

## The kill switch
Two server settings (`.env`), both required:

| Setting | Meaning |
|---|---|
| `BRAND_PROBE_ENABLED=true` | Master switch. `false` (the default): nothing is queued, the worker API answers 503 to everything, late results are refused. Flip it back to `false` to stop all probing immediately. |
| `BRAND_PROBE_KEY=<long random string>` | The shared signing secret. Empty means off even if the switch is on. Generate with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. |

Optional limits: `BRAND_PROBE_TENANT_DAILY_CAP` (default 50 jobs per tenant per day), `BRAND_PROBE_HOST_INTERVAL_HOURS` (default 24, so a host is probed at most once a day), `BRAND_PROBE_JOB_TTL_SECONDS` (default 900: an unclaimed job expires).

Which look-alikes get probed: live (resolving or beyond), not dismissed, and either confirmed or resembling the brand enough to need a decision. Most abusive first, up to the daily cap.

## Setting up the worker machine: the script
**Never copy the whole `backend/` folder to the worker.** It holds the app's `.env`, database settings, dev data and generated passwords, and the worker machine fetches pages from hostile hosts. Send only the worker's files. From the repository's `backend/` parent folder (Windows 10+ has `tar` built in):

```
tar -czf zp-worker.tgz -C backend --exclude=__pycache__ probe_worker app/services/safe_fetch.py app/services/brand_probe_protocol.py
scp -i <your-key>.pem zp-worker.tgz ubuntu@<worker-address>:~/
```

Then on the worker: `mkdir ~/zp && tar -xzf zp-worker.tgz -C ~/zp && cd ~/zp`. The script refuses to run if it finds an `.env` or a `data` folder next to it, which means a full copy was sent.

On a **fresh, single-purpose** Debian or Ubuntu VPS (not your app host, not your AWS project), from that folder run:

```
sudo bash probe_worker/setup_worker.sh --api https://your-api-host --generate-key
```

`--generate-key` makes the signing key, stores it root-only, and prints it **once** at the end for you to set as `BRAND_PROBE_KEY` on the API. Use `--key-file FILE` (or the `ZP_KEY` variable, or the prompt) to supply an existing one. The script installs Docker and Python, creates the unprivileged `zpworker` user, installs the worker's files root-owned and read-only, builds the renderer image, creates the `zp-render` network, adds the firewall rules, **tests the rules** (a container must not reach the host or the metadata address, and neither must the worker's own traffic; both must still reach the public internet), and starts the service only if the tests pass. It is safe to run again. `--no-start` installs without starting, `--skip-tests` skips the firewall tests (not recommended), and `sudo bash probe_worker/setup_worker.sh --uninstall` removes everything it installed. The first run takes several minutes because the browser image is large.

The script has been syntax-checked and its helpers tested, but it has **not been run on a real machine yet**. Run it on a throwaway VPS first, read what it prints, and keep the firewall tests on. The manual steps below are what it does, for reference or if you would rather do them by hand. Note the script also blocks 100.64.0.0/10 (carrier-grade NAT) and, for the worker's own traffic, allows only the specific DNS servers and API address it finds on private addresses.

## Running the worker on AWS EC2
Written for the case where the machine would be an Ubuntu EC2 instance you already have (one that used to run an LMS and was connected to PathProof). **None of the AWS commands below have been run by whoever wrote them: read each one, and check the names and IDs, before running it.** The AWS connection was not available when this was written.

**Why EC2 needs more care than an ordinary VPS.** AWS's acceptable-use terms restrict probing other systems without authorization, so abuse reports from suspect hosts can be taken up against the **project**, not just the instance. Put the worker in its own AWS project (create it in AWS Settings) so a complaint cannot reach anything else, such as PathProof. If it must stay in your existing project, treat it as a short, low-volume trial and isolate it as below. Many phishing pages also block cloud address ranges, so expect more "page may differ for real visitors" results than from a non-cloud address.

**1. Retire the old machine first; do not reuse it.** An instance that ran an LMS has leftover users, keys, services, a database and possibly student data (personal information: delete it properly, or export what you need first). Rebuild instead of repurposing:
- Export anything you still need, then stop the LMS.
- Remove DNS records that point at the instance's address (a record pointing at an address that someone else later gets is a takeover risk).
- In PathProof, delete the host connection for this machine (and, if you like, the key), so it does not keep an SSH key for a machine that no longer exists.
- Terminate the instance, then delete what it leaves behind: its volumes, snapshots and any Elastic IP you no longer need. Do this only after you have checked what each of them is.

**2. A new network for the worker only** (replace `<region>` with your project's selected Region; the worker must stay in it):
```
VPC=$(aws ec2 create-vpc --cidr-block 10.50.0.0/24 --query Vpc.VpcId --output text)
IGW=$(aws ec2 create-internet-gateway --query InternetGateway.InternetGatewayId --output text)
aws ec2 attach-internet-gateway --internet-gateway-id $IGW --vpc-id $VPC
SUBNET=$(aws ec2 create-subnet --vpc-id $VPC --cidr-block 10.50.0.0/26 --query Subnet.SubnetId --output text)
RT=$(aws ec2 create-route-table --vpc-id $VPC --query RouteTable.RouteTableId --output text)
aws ec2 create-route --route-table-id $RT --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW
aws ec2 associate-route-table --route-table-id $RT --subnet-id $SUBNET
```
A VPC with nothing else in it means there is no private network for a compromised page to reach.

**3. A narrow security group.** Inbound: SSH from your own address only. Outbound: replace the default allow-everything rule with web traffic, DNS and nothing else.
```
SG=$(aws ec2 create-security-group --group-name zoneproof-worker --description "ZoneProof worker" --vpc-id $VPC --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id $SG --protocol tcp --port 22 --cidr <your.ip.address>/32
aws ec2 revoke-security-group-egress --group-id $SG --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'
aws ec2 authorize-security-group-egress --group-id $SG --ip-permissions \
  'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0}]' 'IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=0.0.0.0/0}]' \
  'IpProtocol=udp,FromPort=53,ToPort=53,IpRanges=[{CidrIp=10.50.0.2/32}]' 'IpProtocol=tcp,FromPort=53,ToPort=53,IpRanges=[{CidrIp=10.50.0.2/32}]'
```
(10.50.0.2 is the VPC's DNS server: the network's base address plus two.) A security group cannot block private addresses by itself, which is why the script's firewall rules still matter.

**4. The instance.** Ubuntu 24.04, at least 2 GB of memory (`t3.small`; a 1 GB size cannot run the renderer), an encrypted volume, **no IAM role** (so no AWS credentials exist on the box), and the instance metadata service locked down (version 2 only, one hop, so a container cannot reach it):
```
AMI=$(aws ssm get-parameters --names /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query 'Parameters[0].Value' --output text)
aws ec2 run-instances --image-id $AMI --instance-type t3.small --key-name <your-key-pair> --subnet-id $SUBNET --security-group-ids $SG \
  --associate-public-ip-address --metadata-options HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=30,VolumeType=gp3,Encrypted=true}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=zoneproof-worker}]'
```
Optionally allocate and attach an Elastic IP so the address survives a stop and start (it costs a little while unattached). Keep the project's abuse-contact email current and answer reports quickly.

**5. Then the script, as for any other machine.** Send the worker package (see the top of the script section: only the worker's files, never the whole `backend/` folder) and run `sudo bash probe_worker/setup_worker.sh --api https://your-api-host --generate-key`. On AWS it will find the VPC's private DNS server and allow it on port 53 only, for the worker and for the renderer containers, and its self-tests check that names resolve from both. If those fail, nothing is started.

**6. After you are done with any AWS resources you create for this**, decide whether to keep or delete each one, so nothing keeps costing money.

## Setting up the worker machine: by hand
1. Provision a small VPS on a provider whose acceptable-use terms allow security research. **Not** on the app host or its cloud account (see the design brief, point 2).
2. Firewall: allow outbound to the internet and to your API; block outbound to private, link-local and metadata ranges (169.254.0.0/16, 10/8, 172.16/12, 192.168/16, fc00::/7). The code refuses these too, but the firewall is the layer that does not depend on the code.
3. Copy to the machine: the `backend/probe_worker/` folder, `backend/app/services/safe_fetch.py` and `backend/app/services/brand_probe_protocol.py`, keeping the `app/services/` layout (the worker imports only those two modules). `pip install httpx`.
4. Run as an unprivileged user, ideally in a container with no volume mounts:
   ```
   ZP_API=https://your-api-host  ZP_KEY=<the same key>  python probe_worker/worker.py
   ```
5. Turn the switch on at the API. The Brand Guard drawer's "What its web page showed" section fills in as results arrive; `GET /brand-guard/probe-status` shows when the worker last collected a job.

**The API path must be what the worker signs.** The signature covers the exact request path, so the worker must call the API directly, not through a proxy that adds or strips a path prefix.

## How often the worker asks the API for work
When there is no job (or the API answers 503 because probing is off) the worker waits **60 seconds** before asking again, so an idle worker makes about one small request a minute to your API. Change it with `ZP_IDLE_SLEEP` (seconds, kept between 5 and 600) in `/etc/zoneproof-worker.env`. A queued job can therefore wait up to that long to be collected. This polling only goes to your own API; it has no effect on what suspect hosts or your provider see.

## What the worker does to a suspect host
- `GET http://<host>/` with up to 3 redirects, each hop re-validated (public addresses only, connection pinned to the checked address). It identifies itself as `ZoneProof-Probe/1`.
- `GET` of the page's icon (or `/favicon.ico`), capped at 64 KB.
- One TLS handshake to read the certificate, even an invalid one.
- Never: submits a form, types anything, clicks, runs a script, downloads beyond the capped read, or follows a redirect to a non-public address.

## What is kept (light probe)
From each result the API keeps only extracted facts on the candidate (redirect chain, page title, whether a password form exists and where it posts, the icon's hash, certificate facts, whether a challenge page appeared). **The page HTML is dropped as soon as it is analysed and is never stored or shown.**

## The renderer (step 7.3): a second switch, a container per job
Everything above covers the light probe. The renderer adds a real browser: it loads the page, lets its scripts run, and records a screenshot, the visible text, the forms (including a password field a script creates) and the navigation redirects. It is **off by default and has its own switch**, on top of the two above:

| Setting | Meaning |
|---|---|
| `BRAND_RENDER_ENABLED=true` | Turns the renderer on. `false` (the default): render jobs are never handed out and a render result is refused. Needs `BRAND_PROBE_ENABLED` and `BRAND_PROBE_KEY` too. |
| `BRAND_RENDER_TENANT_DAILY_CAP` | Render jobs per tenant per day (default 10). |
| `BRAND_RENDER_HOST_INTERVAL_DAYS` | A host is rendered at most once in this many days (default 7). |
| `BRAND_CAPTURE_RETENTION_DAYS` | How long a screenshot and page text are kept (default 30). |

**What gets rendered:** only look-alikes the light probe already found interesting (a password form, the brand's name in the title, the brand's own icon) or that a person has confirmed, never a page that redirects to the brand's own site, never a dismissed one.

**On the worker machine (needs Docker):**
1. Build the image once, from the `backend/` folder: `docker build -f probe_worker/Dockerfile.render -t zoneproof-render:1 .`
2. Create the network the containers use: `docker network create zp-render`. Then **block private ranges for that network at the host firewall** (in the `DOCKER-USER` chain, drop traffic from the network's subnet to 10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7 and the host itself). This firewall rule is the hard control. The code checks every request too, but a browser does its own DNS lookups, so a name that changes its answer between our check and the browser's request is only reliably stopped by the firewall.
3. The worker user needs permission to run `docker run` and `docker kill`. Nothing else changes: `python probe_worker/worker.py` starts a throwaway container for each render job.
4. Optional: `ZP_RENDER_IMAGE` and `ZP_RENDER_NETWORK` override the image and network names.

**What the container is:** a fresh headless Chromium per job, destroyed afterwards. Read-only filesystem (a small `noexec` tmpfs), all Linux capabilities dropped, no new privileges, non-root user, 1 GB memory, 1 CPU, 256 processes, no mounts, no environment variables. It never receives the signing key or the API address: the worker starts it with one hostname and reads one JSON result from it. Chromium needs `--no-sandbox` inside a container; the container is the sandbox.

**What the browser may do:** only `GET` and `HEAD`, only http and https on ports 80 and 443, only public addresses, at most 200 requests per page (measured: an ordinary WordPress home page makes about 140; a limit of 60 left the screenshot blank). A script that tries to POST is refused, so a form can never be submitted. Downloads, dialogs, popups, service workers and permissions are all blocked. Nothing is clicked or typed.

**What is kept:** the screenshot and page text are Fernet-encrypted in `brand_page_captures` and shown only to the tenant that owns the look-alike. They are deleted after 30 days by the hourly job, unless the look-alike has become a case (confirmed or in takedown), because a takedown may need them. Only the last 3 captures per look-alike are kept. The candidate itself only gets small extracted facts (forms, where they post, whether a password form appeared only after scripts ran). The page text is shown in the drawer as plain, escaped text, labelled untrusted.

**What the renderer cannot promise:** cloaking still applies (a page that hides from scanners shows the browser something harmless), a headless browser has detectable traits, and a hostile page is attacking a real browser engine. The container, the firewall and the throwaway lifetime limit the damage; keep the image rebuilt on current Playwright releases.

## Similarity (step 7.4)
Full write-up, with what was measured and what it means: `BRAND_GUARD_STAGE7_SIMILARITY.md`. In short, the API compares a look-alike with the brand in three ways: icon (a near copy, weight +8), wording (+10 or +14), and page look (screenshot layout plus accent colours, **weight 0**, shown beside the customer's own page). Operationally:
- **Rebuild each brand's fingerprint once** (Brand profile, rebuild) so it holds the icon hash and hashed wording. Until then icon and wording comparisons do not happen.
- With the renderer on, the worker also renders **the customer's own page** (a `ref` job, same container, same limits) once per brand and every `BRAND_REFERENCE_REFRESH_DAYS` (default 30). Nothing extra to configure on the worker.
- The thresholds and weights are expert-set from a synthetic test, not measured on real phishing pages.

## What this does not do yet
- No JARM. The evidence pack does not yet include the screenshot.
- A page that hides from scanners may show the probe something harmless. A challenge or block is recorded as "may differ for real visitors", and a clean page never clears a look-alike.
- The weights these facts carry in the score (password form 10, posting to another site +10, brand name in the title +8, copied icon 12, odd certificate 5, redirect to the brand's own site -12) are **expert-set assumptions**, not measurements.

## Troubleshooting
- Worker gets 503: the switch is off or the key is empty on the API.
- Worker gets 401: the keys differ, the clocks differ by more than 60 seconds, or a proxy changed the path.
- Nothing is queued: check the candidates are live and not dismissed, the daily cap, and that a scan has run since the switch was turned on (jobs are queued at the end of each scan).
