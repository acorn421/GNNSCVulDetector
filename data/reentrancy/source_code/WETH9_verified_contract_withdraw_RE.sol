/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `withdrawalInProgress` mapping to track ongoing withdrawals, creating persistent state between transactions.
 * 
 * 2. **Moved External Call Before State Updates**: Changed from `transfer()` to `call.value()` and moved it before balance updates, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls withdraw(), `withdrawalInProgress[attacker]` is set to true
 *    - **During external call**: Attacker's fallback function is triggered, but balance hasn't been updated yet
 *    - **Transaction 2**: From fallback, attacker calls withdraw() again on a different address they control
 *    - **Transaction 3**: Original call completes, updating balance incorrectly
 * 
 * 4. **State Persistence**: The `withdrawalInProgress` flag persists across transactions, but the vulnerability allows manipulation of this state through reentrancy combined with multiple addresses.
 * 
 * 5. **Realistic Scenario**: This appears to be a "fix" for double-withdrawal protection but actually creates a vulnerability by performing external calls before state updates.
 * 
 * **Exploitation requires multiple transactions because:**
 * - Initial transaction sets up the vulnerable state
 * - Reentrancy during external call allows state manipulation
 * - Multiple addresses can be used to bypass the withdrawal lock
 * - The vulnerability depends on the persistent state from previous transactions
 * 
 * This creates a genuine multi-transaction vulnerability that cannot be exploited atomically in a single transaction.
 */
pragma solidity ^0.4.18;

contract WETH9 {
    string public name     = "Wrapped Ether";
    string public symbol   = "WETH";
    uint8  public decimals = 18;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);
    event  Deposit(address indexed dst, uint wad);
    event  Withdrawal(address indexed src, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;
    // ======= ADDED: TRACKING MAPPING TO FIX COMPILATION ERROR =======
    mapping (address => bool) private withdrawalInProgress;

    function() public payable {
        deposit();
    }
    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        Deposit(msg.sender, msg.value);
    }
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track withdrawal in progress to prevent double withdrawal
        require(!withdrawalInProgress[msg.sender], "Withdrawal already in progress");
        withdrawalInProgress[msg.sender] = true;
        
        // Perform external call before completing state updates
        if (msg.sender.call.value(wad)()) {
            // Only update balance if transfer succeeds
            balanceOf[msg.sender] -= wad;
            withdrawalInProgress[msg.sender] = false;
            Withdrawal(msg.sender, wad);
        } else {
            // Reset withdrawal flag on failure
            withdrawalInProgress[msg.sender] = false;
            revert("Transfer failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function totalSupply() public view returns (uint) {
        return this.balance;
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint wad)
        public
        returns (bool)
    {
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != uint(-1)) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        Transfer(src, dst, wad);

        return true;
    }
}
