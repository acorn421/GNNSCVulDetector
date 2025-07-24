/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the destination address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added contract detection using `dst.code.length > 0`
 * 2. Introduced external call to `onTokenReceived` function on destination contract
 * 3. External call occurs BEFORE balance updates, creating classic reentrancy vulnerability
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * - **Transaction 1**: Attacker deploys malicious contract with `onTokenReceived` function
 * - **Transaction 2**: Attacker approves themselves or another address to spend tokens
 * - **Transaction 3**: Attacker calls `transferFrom` to their malicious contract
 * - **During External Call**: Malicious contract re-enters `transferFrom` multiple times before original state updates complete
 * - **Result**: Multiple transfers occur but only one set of balance deductions happen
 * 
 * **Why Multi-Transaction Required:**
 * 1. **Setup Phase**: Attacker must deploy malicious contract and set up allowances first
 * 2. **State Accumulation**: Multiple approvals and balance conditions must be established
 * 3. **Exploitation**: The reentrancy only works when transferring TO a malicious contract that can call back
 * 4. **Realistic Scenario**: This mirrors real-world attacks where attackers prepare infrastructure over multiple transactions
 * 
 * **Exploitation Flow:**
 * 1. Deploy malicious contract with `onTokenReceived` that calls `transferFrom` again
 * 2. Set up allowances for the attack scenario
 * 3. Call `transferFrom` with malicious contract as destination
 * 4. During callback, drain funds through multiple re-entrant calls before balances are updated
 * 
 * This creates a realistic vulnerability that requires preparation across multiple transactions and exploits the classic reentrancy pattern of external calls before state updates.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function transferFrom(address src, address dst, uint wad)
        public
        returns (bool)
    {
        require(balanceOf(src) >= wad);

        if (src != msg.sender && allowance(src, msg.sender) != uint(-1)) {
            require(allowance(src, msg.sender) >= wad);
            uint newAllowance = allowance(src, msg.sender) - wad;
            // This is just an interface, so actual state update would be in implementation
        }

        // Check if destination is a contract and call its onTokenReceived function
        if (isContract(dst)) {
            bytes4 onTokenReceivedSelector = bytes4(keccak256("onTokenReceived(address,address,uint256)"));
            dst.call(onTokenReceivedSelector, src, dst, wad);
        }

        // State updates are omitted in interface
        // Transfer(src, dst, wad); // Interface can't emit events

        return true;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    function approve(address spender, uint value) public;
    event Approval(address indexed owner, address indexed spender, uint value);
    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
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

    function deposit(uint wad) public {
        ERC20(usdt_addr).transferFrom(msg.sender, address(this), wad);
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
