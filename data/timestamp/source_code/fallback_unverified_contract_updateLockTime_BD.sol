/*
 * ===== SmartInject Injection Details =====
 * Function      : updateLockTime
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue. The contract allows the owner to update lock times based on timestamp comparisons that can be manipulated by miners. The vulnerability requires multiple transactions: first calling updateLockTime() to set the state variables (lock_time_updates and last_update_timestamp), then calling emergencyTimeExtension() to exploit the timestamp-dependent logic. A malicious miner could manipulate block timestamps to bypass time restrictions and extend lock times inappropriately, potentially preventing legitimate withdrawals or extending lock periods beyond intended limits.
 */
pragma solidity ^0.4.11;

contract ERC20_Transferable {
    function balanceOf(address addr) public returns(uint);
    function transfer(address to, uint value) public returns (bool);
}

contract TimeLockedRewardFaucet {

    // =========== CONFIG START =========== 
    address constant public MULTISIG_OWNER = 0xe18Af0dDA74fC4Ee90bCB37E45b4BD623dC6e099;
    address constant public TEAM_WALLET = 0x008cdC9b89AD677CEf7F2C055efC97d3606a50Bd;

    ERC20_Transferable public token = ERC20_Transferable(0x7C5A0CE9267ED19B22F8cae653F198e3E8daf098);
    uint  public LOCK_RELASE_TIME = now + 15 minutes; //block.timestamp(4011221) == 1499846591
    uint  public WITHDRAWAL_END_TIME = LOCK_RELASE_TIME + 10 minutes;
    // =========== CONFIG END ===========

    address[] public team_accounts;
    uint      public locked_since = 0;
    uint      amount_to_distribute;

    function all_team_accounts() external constant returns(address[]) {
        return team_accounts;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint public lock_time_updates = 0;
    uint public last_update_timestamp = 0;
    
    function updateLockTime(uint new_lock_time) external 
    only(MULTISIG_OWNER) {
        // Allow updates only if current time is close to original lock time
        // Vulnerable: relies on block.timestamp which can be manipulated
        require(now >= LOCK_RELASE_TIME - 30 minutes);
        require(now <= LOCK_RELASE_TIME + 30 minutes);
        
        // Track update attempts - stateful vulnerability
        lock_time_updates++;
        last_update_timestamp = now;
        
        // Only allow extension, not reduction (but vulnerable to timestamp manipulation)
        if (new_lock_time > LOCK_RELASE_TIME) {
            LOCK_RELASE_TIME = new_lock_time;
            WITHDRAWAL_END_TIME = LOCK_RELASE_TIME + 10 minutes;
        }
    }
    
    function emergencyTimeExtension() external 
    only(MULTISIG_OWNER) {
        // Multi-step vulnerability: requires updateLockTime to be called first
        require(lock_time_updates > 0);
        require(last_update_timestamp > 0);
        
        // Vulnerable: depends on timestamp comparison that can be manipulated
        // Attacker can manipulate timestamp to make this condition true
        if (now - last_update_timestamp < 1 hours) {
            // Emergency extension allows bypassing normal time constraints
            LOCK_RELASE_TIME = now + 1 days;
            WITHDRAWAL_END_TIME = LOCK_RELASE_TIME + 10 minutes;
            lock_time_updates = 0; // Reset counter
        }
    }
    // === END FALLBACK INJECTION ===

    function timeToUnlockDDHHMM() external constant returns(uint[3]) {
        if (LOCK_RELASE_TIME > now) {
            uint diff = LOCK_RELASE_TIME - now;
            uint dd = diff / 1 days;
            uint hh = diff % 1 days / 1 hours;
            uint mm = diff % 1 hours / 1 minutes;
            return [dd,hh,mm];
        } else {
            return [uint(0), uint(0), uint(0)];
        }
    }

    function start() external
    only(MULTISIG_OWNER)
    inState(State.INIT){
        locked_since = now;
    }

    function () payable {
        msg.sender.transfer(msg.value); //pay back whole amount sent

        State state = _state();
        if (state==State.INIT) {
            //collect addresses for payout
            require(indexOf(team_accounts,msg.sender)==-1);
            team_accounts.push(msg.sender);
        } else if (state==State.WITHDRAWAL) {
            // setup amount to distribute
            if (amount_to_distribute==0) amount_to_distribute = token.balanceOf(this);
            //payout processing
            require(indexOf(team_accounts, msg.sender)>=0);
            token.transfer(msg.sender,  amount_to_distribute / team_accounts.length);
        } else if (state==State.CLOSED) {
            //collect unclaimed token to team wallet
            require(msg.sender == TEAM_WALLET);
            var balance = token.balanceOf(this);
            token.transfer(msg.sender, balance);
        } else {
            revert();
        }
    }

    enum State {INIT, LOCKED, WITHDRAWAL, CLOSED}
    string[4] labels = ["INIT", "LOCKED", "WITHDRAWAL", "CLOSED"];

    function _state() internal returns(State) {
        if (locked_since == 0)               return State.INIT;
        else if (now < LOCK_RELASE_TIME)     return State.LOCKED;
        else if (now < WITHDRAWAL_END_TIME)  return State.WITHDRAWAL;
        else return State.CLOSED;
    }

    function state() constant public returns(string) {
        return labels[uint(_state())];
    }

    function indexOf(address[] storage addrs, address addr) internal returns (int){
         for(uint i=0; i<addrs.length; ++i) {
            if (addr == addrs[i]) return int(i);
        }
        return -1;
    }

    //fails if state dosn't match
    modifier inState(State s) {
        if (_state() != s) revert();
        _;
    }

    modifier only(address allowed) {
        if (msg.sender != allowed) revert();
        _;
    }

}
