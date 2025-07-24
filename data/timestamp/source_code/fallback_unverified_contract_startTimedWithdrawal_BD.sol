/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimedWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability exploits timestamp manipulation in a multi-transaction withdrawal process. The vulnerability is stateful and requires multiple transactions: first calling startTimedWithdrawal() to initiate a withdrawal with timestamp recording, then calling completeTimedWithdrawal() after the delay period. Miners can manipulate the 'now' timestamp within a 900-second window, allowing them to potentially bypass the intended delay or create timing attacks. The vulnerability persists across transactions through the withdrawalTimestamps and pendingWithdrawals mappings, making it a true multi-transaction stateful vulnerability.
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
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) public withdrawalTimestamps;
    mapping(address => uint256) public pendingWithdrawals;
    uint256 public constant WITHDRAWAL_DELAY = 1 hours;
    // === END FALLBACK INJECTION ===

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

    // === FALLBACK INJECTION: Timestamp Dependence (functions preserved) ===
    function startTimedWithdrawal(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        require(pendingWithdrawals[msg.sender] == 0, "Withdrawal already pending");
        
        pendingWithdrawals[msg.sender] = amount;
        withdrawalTimestamps[msg.sender] = now;
        
        emit Transfer(msg.sender, address(0), amount);
    }
    
    function completeTimedWithdrawal() public {
        require(pendingWithdrawals[msg.sender] > 0, "No pending withdrawal");
        require(now >= withdrawalTimestamps[msg.sender] + WITHDRAWAL_DELAY, "Withdrawal delay not met");
        
        uint256 amount = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        withdrawalTimestamps[msg.sender] = 0;
        
        balanceOf[msg.sender] = sub(balanceOf[msg.sender], amount);
        uint256 ethOut = div(amount, 1000000000);
        
        if(address(this).balance >= ethOut) {
            msg.sender.transfer(ethOut);
            emit Withdrawal(msg.sender, ethOut);
        }
    }
    
    function cancelTimedWithdrawal() public {
        require(pendingWithdrawals[msg.sender] > 0, "No pending withdrawal");
        
        pendingWithdrawals[msg.sender] = 0;
        withdrawalTimestamps[msg.sender] = 0;
    }
    // === END FALLBACK INJECTION ===

}
