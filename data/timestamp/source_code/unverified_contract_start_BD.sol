/*
 * ===== SmartInject Injection Details =====
 * Function      : start
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent vulnerability where the function checks if there's a grace period (5 minutes) from the last start time and provides bonus rewards based on the time difference. This creates a multi-transaction exploit where:
 * 
 * 1. **Transaction 1**: Attacker calls start() to set initial locked_since timestamp
 * 2. **Transaction 2**: Attacker immediately calls start() again within the grace period to trigger the bonus calculation
 * 3. **Exploitation**: The bonus calculation uses (now - locked_since) in a way that miners can manipulate by controlling block timestamps, allowing them to maximize the bonus by setting timestamps strategically across multiple blocks
 * 
 * The vulnerability is stateful because:
 * - locked_since persists between transactions
 * - The bonus calculation depends on the time difference between previous and current start calls
 * - The amount_to_distribute state is modified based on timestamp manipulation
 * 
 * The vulnerability is multi-transaction because:
 * - Requires at least 2 calls to start() to trigger the bonus logic
 * - The first call sets up the state (locked_since)
 * - The second call exploits the timestamp difference for bonus calculation
 * - Cannot be exploited in a single transaction since it requires locked_since to be set first
 * 
 * Miners can manipulate block.timestamp (now) within the ~900 second drift tolerance to maximize the bonus reward calculation, potentially extracting more tokens than intended from the contract.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Add timestamp validation with grace period for restart capability
        if (locked_since > 0 && now - locked_since < 300) { // 5 minute grace period
            // Allow early restart if within grace period - reward calculation bonus
            amount_to_distribute = token.balanceOf(this) + (token.balanceOf(this) * (300 - (now - locked_since))) / 3000; // 10% bonus scaling
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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