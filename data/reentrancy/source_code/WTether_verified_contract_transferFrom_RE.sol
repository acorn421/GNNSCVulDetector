/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the destination address before state updates. This creates a Checks-Effects-Interactions (CEI) pattern violation where:
 * 
 * 1. **Specific Changes Made:**
 *    - Added a low-level call to `dst.call()` with `onTransferReceived` callback
 *    - The external call occurs BEFORE the critical state updates (`balanceOf[src] -= wad` and `balanceOf[dst] += wad`)
 *    - The callback provides the malicious contract with current state information before changes are applied
 * 
 * 2. **Multi-Transaction Exploitation Pattern:**
 *    - **Transaction 1**: Attacker contract calls transferFrom, triggering the callback during the external call
 *    - **During callback**: Malicious contract observes current balances/allowances and records state
 *    - **Transaction 2**: Attacker uses recorded state to call transferFrom again with calculated parameters
 *    - **Exploitation**: The second call can manipulate balances based on the state observed in the first transaction's callback
 * 
 * 3. **Why Multiple Transactions Are Required:**
 *    - The vulnerability requires state accumulation across calls - the malicious contract needs to observe and record state during the first transaction's callback
 *    - The actual exploitation happens in subsequent transactions when the recorded state is used to calculate optimal attack parameters
 *    - A single transaction cannot exploit this because the attacker needs to analyze the state observed during the callback and then craft a follow-up transaction
 *    - The stateful nature means each transaction's callback provides information that enables more sophisticated attacks in future transactions
 * 
 * This creates a realistic vulnerability where the external call allows state observation and manipulation across multiple transactions, making it a genuine multi-transaction, stateful reentrancy vulnerability.
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

    function deposit(uint wad) public {
        ERC20(usdt_addr).transferFrom(msg.sender, address(this), wad);
        balanceOf[msg.sender] += wad;
        emit Deposit(msg.sender, wad);
    }
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        ERC20(usdt_addr).transfer(msg.sender, wad);
        emit Withdrawal(msg.sender, wad);
    }

    function totalSupply() public view returns (uint) {
        return address(this).balance;
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify destination contract before state changes (vulnerable pattern)
        if (isContract(dst)) {
            // External call before state update - classic CEI violation
            dst.call(
                bytes4(keccak256("onTransferReceived(address,address,uint256)")),
                src,
                dst,
                wad
            );
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        emit Transfer(src, dst, wad);

        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
