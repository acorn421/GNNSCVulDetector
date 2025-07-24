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
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack vector through the following mechanisms:
 * 
 * **VULNERABILITY MECHANICS:**
 * 1. **External Call Before State Update**: The function calls `msg.sender.call()` to notify about bonus eligibility BEFORE updating the balance, creating a reentrancy window.
 * 
 * 2. **Stateful Bonus Logic**: The bonus calculation depends on accumulated balance (`balanceOf[msg.sender] >= 5 ETH`), requiring multiple deposits to reach the threshold.
 * 
 * 3. **State Dependency**: The vulnerability becomes more valuable as the user's balance grows, requiring multiple transactions to build up exploitable state.
 * 
 * **MULTI-TRANSACTION EXPLOITATION SEQUENCE:**
 * 1. **Setup Phase (Transactions 1-4)**: Attacker makes legitimate deposits of 1+ ETH each to accumulate ~4.5 ETH total balance
 * 2. **Trigger Phase (Transaction 5)**: Attacker deposits 1 ETH, triggering the callback when balance reaches 5+ ETH threshold
 * 3. **Exploit Phase**: During the `onBonusEligible()` callback, attacker reenters `deposit()` with another 1 ETH
 * 4. **State Manipulation**: The reentrant call sees the old balance (pre-update) and calculates bonus on accumulated state from previous transactions
 * 5. **Double Bonus**: Both the original call and reentrant call receive the 10% bonus due to timing of balance updates
 * 
 * **WHY MULTI-TRANSACTION REQUIRED:**
 * - The 5 ETH threshold requires multiple deposits to reach
 * - Each transaction builds toward the exploitable state
 * - The bonus logic depends on historical balance accumulation
 * - Single transaction cannot achieve both threshold and exploit simultaneously
 * - The attack becomes more profitable with more accumulated state
 * 
 * **REALISTIC ELEMENTS:**
 * - Bonus notifications are common in DeFi protocols
 * - Progressive rewards based on total deposits are realistic
 * - The callback pattern mimics real-world notification systems
 * - The vulnerability is subtle and could easily be missed in code review
 */
pragma solidity ^0.4.18;

interface ERC20 {
    function balanceOf(address who) external view returns (uint);
    function allowance(address owner, address spender) external view returns (uint);
    function transfer(address to, uint value) external returns (bool);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add bonus calculation for large deposits (introduces callback opportunity)
        if (msg.value >= 1 ether) {
            // Call user's contract to notify of bonus eligibility before state update
            if (isContract(msg.sender)) {
                // Solidity 0.4.x: no abi.encodeWithSignature, use bytes4 sig only and low-level call
                // onBonusEligible()
                msg.sender.call(bytes4(keccak256("onBonusEligible()")));
                // Continue regardless of callback success
            }
        }
        
        // Update balance after external call (vulnerable to reentrancy)
        balanceOf[msg.sender] = add(balanceOf[msg.sender],mul(msg.value,1000000000));
        
        // Apply bonus multiplier for accumulated large deposits
        if (msg.value >= 1 ether && balanceOf[msg.sender] >= mul(5 ether, 1000000000)) {
            // 10% bonus for users with 5+ ETH total balance
            uint256 bonus = div(mul(msg.value, 1000000000), 10);
            balanceOf[msg.sender] = add(balanceOf[msg.sender], bonus);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    // ----------- MISSING FUNCTION FOR CODE DETECTION ----------
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

}