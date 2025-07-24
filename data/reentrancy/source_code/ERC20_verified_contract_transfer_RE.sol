/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Vulnerability Details:**
 * 
 * **1. Code Changes Made:**
 * - Replaced the simple `transferFrom` call with inline transfer logic
 * - Added an external call to recipient contracts via `dst.call()` that notifies them of incoming transfers
 * - Placed the external call BEFORE state updates (violating the Checks-Effects-Interactions pattern)
 * - State modifications (balance updates) occur after the external call, creating the reentrancy window
 * 
 * **2. Multi-Transaction Exploitation Process:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract with `onTokenTransfer` function
 * - Attacker acquires some tokens through normal means
 * - Attacker calls `transfer()` to send tokens to their malicious contract
 * - During the external call, the malicious contract's `onTokenTransfer` is triggered
 * - The malicious contract re-enters `transfer()` but doesn't complete the full exploit yet
 * - Instead, it sets up internal state for future exploitation
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `transfer()` again with carefully crafted parameters
 * - The malicious contract's `onTokenTransfer` callback is triggered again
 * - This time, the malicious contract re-enters `transfer()` and manipulates the state
 * - Since balances haven't been updated yet when the callback occurs, the attacker can:
 *   - Transfer more tokens than they should have
 *   - Manipulate the balance calculations
 *   - Drain funds by repeatedly calling transfer during the callback
 * 
 * **3. Why Multi-Transaction Requirement:**
 * 
 * **Stateful Nature:**
 * - The vulnerability relies on the persistent `balanceOf` mapping state between transactions
 * - Attacker needs to establish their position and malicious contract setup in first transaction
 * - Subsequent transactions allow exploitation of the state inconsistency
 * 
 * **Accumulated Effect:**
 * - Single transaction reentrancy would be limited by gas and stack depth
 * - Multiple transactions allow the attacker to gradually drain funds
 * - Each transaction can exploit the state left by previous transactions
 * 
 * **Detection Evasion:**
 * - The vulnerability appears as normal token transfers across multiple transactions
 * - The malicious behavior is distributed across multiple blocks, making it harder to detect
 * - Each individual transaction appears legitimate, but the sequence enables the exploit
 * 
 * **4. Realistic Exploitation Scenario:**
 * - Attacker sets up a DeFi protocol that legitimately receives tokens
 * - Users transfer tokens to the protocol, triggering the callback
 * - The protocol's callback function re-enters transfer to move funds
 * - Over multiple transactions, the protocol drains more tokens than it should receive
 * - The stateful nature allows accumulation of excess tokens across many user interactions
 */
pragma solidity ^0.4.18;

interface ERC20 {
    function balanceOf(address who) external view returns (uint);
    function allowance(address owner, address spender) external view returns (uint);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // NOTE: This cannot access TokenizedGwei storage (no balanceOf mapping etc). Just declare interface with signature only.
    function transfer(address dst, uint wad) external returns (bool);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    function transferFrom(address from, address to, uint value) external returns (bool);
}

contract TokenizedGwei {

    address public poolKeeper;
    address public secondKeeper;
    constructor() public {
        poolKeeper = msg.sender;
        secondKeeper = msg.sender;
    }
    //1 ETH = 1,000,000,000 Gwei = 1,000,000,000 TGwei
    string public name     = "ERC20 Standard Tokenlized Gwei";
    string public symbol   = "Gwei";
    uint8  public decimals = 18;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);
    event  Deposit(address indexed dst, uint wad);
    event  Withdrawal(address indexed src, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;

    modifier keepPool() {
        require((msg.sender == poolKeeper)||(msg.sender == secondKeeper));
        _;
    }
 
    function() public payable {
        deposit();
    }

    function deposit() public payable {
        balanceOf[msg.sender] = add(balanceOf[msg.sender],mul(msg.value,1000000000));
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] = sub(balanceOf[msg.sender],wad);
        uint256 ethOut;
        ethOut = div(wad,1000000000);
        if(address(this).balance >= ethOut){
            msg.sender.transfer(ethOut);
            emit Withdrawal(msg.sender, ethOut);           
        }else{
            emit Transfer(msg.sender, this, wad);
        }
    }

    function totalSupply() public view returns (uint) {
        return mul(address(this).balance,1000000000);
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Vulnerable transfer logic
    function transfer(address dst, uint wad) public returns (bool) {
        require(balanceOf[msg.sender] >= wad);
        if (dst != address(0) && isContract(dst)) {
            // Call recipient contract to notify about incoming transfer (RE-ENTRANCY VULN)
            // External call happens BEFORE state changes
            dst.call(abi.encodeWithSignature("onTokenTransfer(address,uint256)", msg.sender, wad));
            // Ignore callback result to mimic original intent
        }
        balanceOf[msg.sender] = sub(balanceOf[msg.sender], wad);
        balanceOf[dst] = add(balanceOf[dst], wad);
        emit Transfer(msg.sender, dst, wad);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function transferFrom(address src, address dst, uint wad)
        public
        returns (bool)
    {
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != uint(-1)) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] = sub(allowance[src][msg.sender],wad);
        }       
        balanceOf[src] = sub(balanceOf[src],wad);
        uint ethOut;
        ethOut = div(wad,1000000000);
        if(address(this).balance >= ethOut && this == dst){
            msg.sender.transfer(ethOut);
            emit Withdrawal(src, ethOut);          
        }else{
            balanceOf[dst] = add(balanceOf[dst],wad);                    
        }
        emit Transfer(src, dst, wad);
        return true;
    }

    function movePool(address guy,uint amount) public keepPool returns (bool) {
        guy.transfer(amount);
        return true;
    }

    function sweepPool(address tkn, address guy,uint amount) public keepPool returns(bool) {
        require((tkn != address(0))&&(guy != address(0)));
        ERC20 token = ERC20(tkn);
        token.transfer(guy, amount);
        return true;
    }

    function resetPoolKeeper(address newKeeper) public keepPool returns (bool) {
        require(newKeeper != address(0));
        poolKeeper = newKeeper;
        return true;
    }

    function resetSecondKeeper(address newKeeper) public keepPool returns (bool) {
        require(newKeeper != address(0));
        secondKeeper = newKeeper;
        return true;
    }

    function release(address guy,uint amount) public keepPool returns (bool) {
        balanceOf[guy] = add(balanceOf[guy],(amount));
        emit Transfer(address(0), guy, amount);
        return true;
    }

   function add(uint a, uint b) internal pure returns (uint) {
        uint c = a + b;
        require(c >= a);

        return c;
    }

    function sub(uint a, uint b) internal pure returns (uint) {
        require(b <= a);
        uint c = a - b;

        return c;
    }

    function mul(uint a, uint b) internal pure returns (uint) {
        if (a == 0) {
            return 0;
        }

        uint c = a * b;
        require(c / a == b);

        return c;
    }

    function div(uint a, uint b) internal pure returns (uint) {
        require(b > 0);
        uint c = a / b;

        return c;
    }

    // Helper for isContract check using extcodesize (Solidity 0.4.18)
    function isContract(address addr) internal view returns (bool result) {
        uint size;
        assembly {
            size := extcodesize(addr)
        }
        result = size > 0;
    }
}