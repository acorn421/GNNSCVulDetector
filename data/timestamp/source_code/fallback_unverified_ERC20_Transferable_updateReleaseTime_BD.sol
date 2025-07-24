/*
 * ===== SmartInject Injection Details =====
 * Function      : updateReleaseTime
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
 * This vulnerability introduces a timestamp dependence issue where the contract allows updating release times through a two-step process. The vulnerability requires multiple transactions: first calling updateReleaseTime() to set a pending time, then calling confirmReleaseTimeUpdate() to confirm it. The confirmation can happen 1 hour before the intended release time, allowing miners to manipulate block timestamps to trigger early confirmations. This creates a stateful vulnerability where the pending_release_time persists between transactions and can be exploited through timestamp manipulation across multiple blocks.
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
    uint public pending_release_time = 0;
    uint public release_time_update_count = 0;
    
    function updateReleaseTime(uint new_release_time) external 
    only(MULTISIG_OWNER) 
    inState(State.INIT) {
        require(new_release_time > now);
        pending_release_time = new_release_time;
        release_time_update_count++;
    }
    
    function confirmReleaseTimeUpdate() external 
    only(MULTISIG_OWNER) {
        require(pending_release_time > 0);
        require(now >= pending_release_time - 1 hours); // Allow confirmation 1 hour before
        
        LOCK_RELASE_TIME = pending_release_time;
        WITHDRAWAL_END_TIME = LOCK_RELASE_TIME + 10 minutes;
        pending_release_time = 0;
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