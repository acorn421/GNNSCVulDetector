/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a callback mechanism to the destination address after balance updates are complete. This creates a reentrancy vulnerability where:
 * 
 * 1. **Transaction 1**: Attacker sets up allowances and balances in specific ratios
 * 2. **Transaction 2**: Attacker calls transferFrom, which triggers the callback
 * 3. **During callback**: Attacker re-enters transferFrom with different parameters, exploiting the fact that their balance was already updated but they can still manipulate other accounts' allowances/balances through additional transfers
 * 
 * The vulnerability is stateful because:
 * - It requires specific balance/allowance configurations set up in prior transactions
 * - The callback occurs after state updates, allowing the attacker to leverage their newly received tokens
 * - Multiple reentrancy calls can drain funds by exploiting the state inconsistencies
 * 
 * The vulnerability is multi-transaction because:
 * - The attacker must first set up the exploitable state (allowances, balances)
 * - Then trigger the vulnerable transfer that enables the callback
 * - The callback can then re-enter with the updated state from the first call
 * - This creates a sequence dependency that cannot be exploited atomically in a single transaction
 */
pragma solidity ^0.4.18;

contract ITokenReceiver {
    function onTokenReceived(address src, uint wad) public;
}

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

    function() public payable {
        deposit();
    }
    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        Deposit(msg.sender, msg.value);
    }
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        msg.sender.transfer(wad);
        Withdrawal(msg.sender, wad);
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient with callback - potential reentrancy point
        if (dst != address(0) && isContract(dst)) {
            ITokenReceiver(dst).onTokenReceived(src, wad);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
