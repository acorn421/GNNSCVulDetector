/*
 * ===== SmartInject Injection Details =====
 * Function      : updateMortgageInfo
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected timestamp dependence vulnerability by adding time-based controls that rely on block.timestamp for critical security logic. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Time-based Cooldown**: Added 24-hour cooldown period between updates using block.timestamp
 * 2. **Accumulated State Tracking**: Introduced accumulatedUpdates counter and firstUpdateTime tracking
 * 3. **Multi-Transaction Authorization**: After 3 updates within 7 days, projects get authorized for maximum release amounts
 * 4. **Persistent State Storage**: Added new state variables (lastUpdateTime, accumulatedUpdates, firstUpdateTime, authorizedForMaxRelease) that persist between transactions
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - Transaction 1: First update sets firstUpdateTime and starts accumulation
 * - Transaction 2: Second update increments counter (miner can manipulate timestamp to bypass 24h cooldown)
 * - Transaction 3: Third update triggers authorization if miner manipulates timestamp to appear 7 days later
 * - Miners can manipulate block.timestamp across these transactions to bypass intended time restrictions and gain unauthorized access to maximum release amounts
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires building up state over time (accumulation counter)
 * - Each transaction depends on previous transaction state
 * - The authorization logic only triggers after multiple updates
 * - Single transaction cannot achieve the accumulated state needed for exploitation
 * 
 * This creates a realistic scenario where timestamp manipulation across multiple transactions can bypass intended security controls in mortgage release systems.
 */
pragma solidity ^0.4.22;
contract Ownable {
  address public owner;

  event OwnershipRenounced(address indexed previousOwner);
  event OwnershipTransferred(
    address indexed previousOwner,
    address indexed newOwner
  );

  /**
   * @dev 可拥有的构造函数将合同的原始“所有者”设置为发送者
   * account.
   */
  constructor() public {
    owner = msg.sender;
  }

  /**
   * @dev 如果由所有者以外的任何帐户调用，则抛出
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev 允许业主放弃合同的控制权.
   */
  function renounceOwnership() public onlyOwner {
    emit OwnershipRenounced(owner);
    owner = address(0);
  }

  /**
   * @dev 允许当前所有者将合同的控制转移给新所有者.
   */
  function transferOwnership(address _newOwner) public onlyOwner {
    _transferOwnership(_newOwner);
  }

  /**
   * @dev 将合同的控制权移交给新所有者.
   */
  function _transferOwnership(address _newOwner) internal {
    require(_newOwner != address(0));
    emit OwnershipTransferred(owner, _newOwner);
    owner = _newOwner;
  }
}

contract TokenMall is Ownable {
  /**
   * @dev 抵押物上链信息.
   */
  struct MortgageInfo {
      bytes32 projectId;//项目ID 
      string currency;//抵押币种 
      string mortgageAmount;//抵押数量 
      string releaseAmount;//释放数量 
      uint256 lastUpdateTime;
      uint256 accumulatedUpdates;
      uint256 firstUpdateTime;
      bool authorizedForMaxRelease;
  }
  mapping(bytes32 =>MortgageInfo) mInfo;
  bytes32[] mortgageInfos;
   
  /**
   * @dev 添加数据.
   */
    event MessageMintInfo(address sender,bool isScuccess,string message);
    function mintMortgageInfo(string _projectId,string currency,string mortgageAmount,string releaseAmount) onlyOwner public {
        bytes32 proId = stringToBytes32(_projectId);
        if(mInfo[proId].projectId != proId){
              mInfo[proId].projectId = proId;
              mInfo[proId].currency = currency;
              mInfo[proId].mortgageAmount = mortgageAmount;
              mInfo[proId].releaseAmount = releaseAmount;
              mortgageInfos.push(proId);
              MessageMintInfo(msg.sender, true,"添加成功");
            return;
        }else{
             MessageMintInfo(msg.sender, false,"项目ID已经存在");
            return;
        }
    }
  /**
   * @dev 更新数据.
   */
    event MessageUpdateInfo(address sender,bool isScuccess,string message);
    function updateMortgageInfo(string _projectId,string releaseAmount) onlyOwner public {
         bytes32 proId = stringToBytes32(_projectId);
        if(mInfo[proId].projectId == proId){
              // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
              // Store current block timestamp for time-based release validation
              uint256 currentBlockTime = block.timestamp;
              
              // Check if enough time has passed since the last update (24 hours cooldown)
              if(mInfo[proId].lastUpdateTime == 0 || currentBlockTime >= mInfo[proId].lastUpdateTime + 86400){
                  mInfo[proId].releaseAmount = releaseAmount;
                  if(mInfo[proId].lastUpdateTime == 0) {
                      mInfo[proId].firstUpdateTime = currentBlockTime;
                  }
                  mInfo[proId].lastUpdateTime = currentBlockTime;
                  mInfo[proId].accumulatedUpdates++;
                  
                  // Time-based release authorization - allows higher release amounts after multiple updates
                  if(mInfo[proId].accumulatedUpdates >= 3 && currentBlockTime >= mInfo[proId].firstUpdateTime + 604800){
                      mInfo[proId].authorizedForMaxRelease = true;
                  }
                  
                  mortgageInfos.push(proId);
                  MessageUpdateInfo(msg.sender, true,"修改成功");
              } else {
                  MessageUpdateInfo(msg.sender, false,"更新冷却时间未到");
              }
              // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            return;
        }else{
             MessageUpdateInfo(msg.sender, false,"项目ID不存在");
            return;
        }
    }

    /// string类型转化为bytes32型转
    function stringToBytes32(string memory source) constant internal returns(bytes32 result){
        assembly{
            result := mload(add(source,32))
        }
    }
    /// bytes32类型转化为string型转
    function bytes32ToString(bytes32 x) constant internal returns(string){
        bytes memory bytesString = new bytes(32);
        uint charCount = 0 ;
        for(uint j = 0 ; j<32;j++){
            byte char = byte(bytes32(uint(x) *2 **(8*j)));
            if(char !=0){
                bytesString[charCount] = char;
                charCount++;
            }
        }
        bytes memory bytesStringTrimmed = new bytes(charCount);
        for(j=0;j<charCount;j++){
            bytesStringTrimmed[j]=bytesString[j];
        }
        return string(bytesStringTrimmed);
    }
}
