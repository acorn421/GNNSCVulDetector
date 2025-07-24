/*
 * ===== SmartInject Injection Details =====
 * Function      : deposit
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Callback Mechanism**: Added an `onDepositReceived` callback to contracts that deposit tokens, creating a reentrancy vector after the initial `transferFrom` call but before balance updates.
 * 
 * 2. **State Update After External Calls**: The critical state update (`balanceOf[msg.sender] += wad`) occurs after both the `transferFrom` call and the callback, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker deploys malicious contract with `onDepositReceived` function
 *    - **Transaction 2**: Attacker calls `deposit()` which triggers the callback
 *    - **During Callback**: The malicious contract can call other functions (like `withdraw()`) while the balance hasn't been updated yet
 *    - **State Accumulation**: Multiple deposit calls create accumulated inconsistent state
 * 
 * 4. **Stateful Nature**: The vulnerability requires:
 *    - Persistent contract state (malicious contract deployment)
 *    - Accumulated balance discrepancies across multiple transactions
 *    - Sequential exploitation that depends on state changes from previous calls
 * 
 * 5. **Realistic Implementation**: The callback mechanism is presented as a "deposit confirmation" feature, which is a realistic pattern that developers might implement for contract-to-contract interactions.
 * 
 * **Exploitation Scenario**:
 * - Attacker deploys malicious contract with `onDepositReceived` that calls `withdraw()`
 * - First transaction: Attacker deposits 100 tokens
 * - During the callback (before balance update), attacker withdraws tokens using old balance
 * - This creates a state where tokens are withdrawn but deposit balance is still incremented
 * - Multiple such transactions compound the vulnerability, draining the contract
 */
pragma solidity ^0.4.18;

/**
 * @title ERC20Basic
 * @dev Simpler version of ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/20
 */
contract ERC20Basic {
    uint public _totalSupply;
    function totalSupply() public constant returns (uint);
    function balanceOf(address who) public constant returns (uint);
    function transfer(address to, uint value) public;
    event Transfer(address indexed from, address indexed to, uint value);
}

/**
 * @title ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/20
 */
contract ERC20 is ERC20Basic {
    function allowance(address owner, address spender) public constant returns (uint);
    function transferFrom(address from, address to, uint value) public;
    function approve(address spender, uint value) public;
    event Approval(address indexed owner, address indexed spender, uint value);
}

contract WTether {
    string public name     = "Wrapped Tether";
    string public symbol   = "WUSDT";
    address usdt_addr = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    uint8  public decimals = 6;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);
    event  Deposit(address indexed dst, uint wad);
    event  Withdrawal(address indexed src, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function deposit(uint wad) public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check for valid deposit amount
        require(wad > 0);
        
        // External call to transfer tokens - potential reentrancy point
        ERC20(usdt_addr).transferFrom(msg.sender, address(this), wad);
        
        // Add callback mechanism for "deposit confirmation" - introduces reentrancy vector
        if (isContract(msg.sender)) {
            // Call onDepositReceived if receiver is a contract
            msg.sender.call(abi.encodeWithSignature("onDepositReceived(uint256)", wad));
            // Continue execution even if callback fails
        }
        
        // State update happens AFTER external calls - classic reentrancy vulnerability
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] += wad;
        Deposit(msg.sender, wad);
    }
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        ERC20(usdt_addr).transfer(msg.sender, wad);
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

        return true;
    }
}
