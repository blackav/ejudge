/* This is auto-generated file */
#include <ctype.h>
#include "ejudge/new_server_proto.h"
int ns_match_action(const unsigned char *str)
{
  int c;
  if (!str) return 0;
  c = str[0];
  if (c == 'l') {
    c = str[1];
    if (c == 'i') {
      c = str[2];
      if (c == 's') {
        c = str[3];
        if (c == 't') {
          c = str[4];
          if (c == '-') {
            c = str[5];
            if (c == 'r') {
              c = str[6];
              if (c == 'u') {
                c = str[7];
                if (c == 'n') {
                  c = str[8];
                  if (c == 's') {
                    c = str[9];
                    if (c == '-') {
                      c = str[10];
                      if (c == 'j') {
                        c = str[11];
                        if (c == 's') {
                          c = str[12];
                          if (c == 'o') {
                            c = str[13];
                            if (c == 'n') {
                              c = str[14];
                              if (!c) return NEW_SRV_ACTION_LIST_RUNS_JSON;
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
          return 0;
        }
        return 0;
      }
      return 0;
    } else if (c < 'i') {
      if (c == 'a') {
        c = str[2];
        if (c == 'n') {
          c = str[3];
          if (c == 'g') {
            c = str[4];
            if (c == 'u') {
              c = str[5];
              if (c == 'a') {
                c = str[6];
                if (c == 'g') {
                  c = str[7];
                  if (c == 'e') {
                    c = str[8];
                    if (c == '-') {
                      c = str[9];
                      if (c == 's') {
                        c = str[10];
                        if (c == 't') {
                          c = str[11];
                          if (c == 'a') {
                            c = str[12];
                            if (c == 't') {
                              c = str[13];
                              if (c == 's') {
                                c = str[14];
                                if (c == '-') {
                                  c = str[15];
                                  if (c == 'p') {
                                    c = str[16];
                                    if (c == 'a') {
                                      c = str[17];
                                      if (c == 'g') {
                                        c = str[18];
                                        if (c == 'e') {
                                          c = str[19];
                                          if (!c) return NEW_SRV_ACTION_LANGUAGE_STATS_PAGE;
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
          return 0;
        }
        return 0;
      }
    } else {
      if (c == 'o') {
        c = str[2];
        if (c == 'g') {
          c = str[3];
          if (c == 'o') {
            c = str[4];
            if (c == 'u') {
              c = str[5];
              if (c == 't') {
                c = str[6];
                if (!c) return NEW_SRV_ACTION_LOGOUT;
                return 0;
              }
              return 0;
            }
            return 0;
          } else if (c < 'o') {
            if (c == 'i') {
              c = str[4];
              if (c == 'n') {
                c = str[5];
                if (!c) return NEW_SRV_ACTION_LOGIN;
                if (c == '-') {
                  c = str[6];
                  if (c == 'p') {
                    c = str[7];
                    if (c == 'a') {
                      c = str[8];
                      if (c == 'g') {
                        c = str[9];
                        if (c == 'e') {
                          c = str[10];
                          if (!c) return NEW_SRV_ACTION_LOGIN_PAGE;
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  } else if (c < 'p') {
                    if (c == 'j') {
                      c = str[7];
                      if (c == 's') {
                        c = str[8];
                        if (c == 'o') {
                          c = str[9];
                          if (c == 'n') {
                            c = str[10];
                            if (!c) return NEW_SRV_ACTION_LOGIN_JSON;
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                  } else {
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
          } else {
          }
          return 0;
        } else if (c < 'g') {
          if (c == 'c') {
            c = str[3];
            if (c == 'k') {
              c = str[4];
              if (c == '-') {
                c = str[5];
                if (c == 'f') {
                  c = str[6];
                  if (c == 'i') {
                    c = str[7];
                    if (c == 'l') {
                      c = str[8];
                      if (c == 't') {
                        c = str[9];
                        if (c == 'e') {
                          c = str[10];
                          if (c == 'r') {
                            c = str[11];
                            if (!c) return NEW_SRV_ACTION_LOCK_FILTER;
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
        } else {
        }
        return 0;
      }
    }
    return 0;
  } else if (c < 'l') {
    if (c == 'f') {
      c = str[1];
      if (c == 'u') {
        c = str[2];
        if (c == 'l') {
          c = str[3];
          if (c == 'l') {
            c = str[4];
            if (c == '-') {
              c = str[5];
              if (c == 'u') {
                c = str[6];
                if (c == 'p') {
                  c = str[7];
                  if (c == 'l') {
                    c = str[8];
                    if (c == 'o') {
                      c = str[9];
                      if (c == 'a') {
                        c = str[10];
                        if (c == 'd') {
                          c = str[11];
                          if (c == '-') {
                            c = str[12];
                            if (c == 'r') {
                              c = str[13];
                              if (c == 'u') {
                                c = str[14];
                                if (c == 'n') {
                                  c = str[15];
                                  if (c == 'l') {
                                    c = str[16];
                                    if (c == 'o') {
                                      c = str[17];
                                      if (c == 'g') {
                                        c = str[18];
                                        if (c == '-') {
                                          c = str[19];
                                          if (c == 'x') {
                                            c = str[20];
                                            if (c == 'm') {
                                              c = str[21];
                                              if (c == 'l') {
                                                c = str[22];
                                                if (!c) return NEW_SRV_ACTION_FULL_UPLOAD_RUNLOG_XML;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              } else if (c < 'u') {
                if (c == 'r') {
                  c = str[6];
                  if (c == 'e') {
                    c = str[7];
                    if (c == 'j') {
                      c = str[8];
                      if (c == 'u') {
                        c = str[9];
                        if (c == 'd') {
                          c = str[10];
                          if (c == 'g') {
                            c = str[11];
                            if (c == 'e') {
                              c = str[12];
                              if (c == '-') {
                                c = str[13];
                                if (c == 'd') {
                                  c = str[14];
                                  if (c == 'i') {
                                    c = str[15];
                                    if (c == 's') {
                                      c = str[16];
                                      if (c == 'p') {
                                        c = str[17];
                                        if (c == 'l') {
                                          c = str[18];
                                          if (c == 'a') {
                                            c = str[19];
                                            if (c == 'y') {
                                              c = str[20];
                                              if (c == 'e') {
                                                c = str[21];
                                                if (c == 'd') {
                                                  c = str[22];
                                                  if (c == '-') {
                                                    c = str[23];
                                                    if (c == '2') {
                                                      c = str[24];
                                                      if (!c) return NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_2;
                                                      return 0;
                                                    } else if (c < '2') {
                                                      if (c == '1') {
                                                        c = str[24];
                                                        if (!c) return NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1;
                                                        return 0;
                                                      }
                                                    } else {
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
              } else {
              }
              return 0;
            }
            return 0;
          }
          return 0;
        }
        return 0;
      } else if (c < 'u') {
        if (c == 'o') {
          c = str[2];
          if (c == 'r') {
            c = str[3];
            if (c == 'g') {
              c = str[4];
              if (c == 'o') {
                c = str[5];
                if (c == 't') {
                  c = str[6];
                  if (c == '-') {
                    c = str[7];
                    if (c == 'p') {
                      c = str[8];
                      if (c == 'a') {
                        c = str[9];
                        if (c == 's') {
                          c = str[10];
                          if (c == 's') {
                            c = str[11];
                            if (c == 'w') {
                              c = str[12];
                              if (c == 'o') {
                                c = str[13];
                                if (c == 'r') {
                                  c = str[14];
                                  if (c == 'd') {
                                    c = str[15];
                                    if (c == '-') {
                                      c = str[16];
                                      if (c == '2') {
                                        c = str[17];
                                        if (!c) return NEW_SRV_ACTION_FORGOT_PASSWORD_2;
                                        return 0;
                                      } else if (c < '2') {
                                        if (c == '1') {
                                          c = str[17];
                                          if (!c) return NEW_SRV_ACTION_FORGOT_PASSWORD_1;
                                          return 0;
                                        }
                                      } else {
                                        if (c == '3') {
                                          c = str[17];
                                          if (!c) return NEW_SRV_ACTION_FORGOT_PASSWORD_3;
                                          return 0;
                                        }
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            } else if (c < 'g') {
              if (c == 'c') {
                c = str[4];
                if (c == 'e') {
                  c = str[5];
                  if (c == '-') {
                    c = str[6];
                    if (c == 's') {
                      c = str[7];
                      if (c == 't') {
                        c = str[8];
                        if (c == 'a') {
                          c = str[9];
                          if (c == 'r') {
                            c = str[10];
                            if (c == 't') {
                              c = str[11];
                              if (c == '-') {
                                c = str[12];
                                if (c == 'v') {
                                  c = str[13];
                                  if (c == 'i') {
                                    c = str[14];
                                    if (c == 'r') {
                                      c = str[15];
                                      if (c == 't') {
                                        c = str[16];
                                        if (c == 'u') {
                                          c = str[17];
                                          if (c == 'a') {
                                            c = str[18];
                                            if (c == 'l') {
                                              c = str[19];
                                              if (!c) return NEW_SRV_ACTION_FORCE_START_VIRTUAL;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
            } else {
            }
            return 0;
          }
          return 0;
        }
      } else {
      }
      return 0;
    } else if (c < 'f') {
      if (c == 'c') {
        c = str[1];
        if (c == 'o') {
          c = str[2];
          if (c == 'n') {
            c = str[3];
            if (c == 't') {
              c = str[4];
              if (c == 'i') {
                c = str[5];
                if (c == 'n') {
                  c = str[6];
                  if (c == 'u') {
                    c = str[7];
                    if (c == 'e') {
                      c = str[8];
                      if (c == '-') {
                        c = str[9];
                        if (c == 'c') {
                          c = str[10];
                          if (c == 'o') {
                            c = str[11];
                            if (c == 'n') {
                              c = str[12];
                              if (c == 't') {
                                c = str[13];
                                if (c == 'e') {
                                  c = str[14];
                                  if (c == 's') {
                                    c = str[15];
                                    if (c == 't') {
                                      c = str[16];
                                      if (!c) return NEW_SRV_ACTION_CONTINUE_CONTEST;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              } else if (c < 'i') {
                if (c == 'e') {
                  c = str[5];
                  if (c == 's') {
                    c = str[6];
                    if (c == 't') {
                      c = str[7];
                      if (c == 's') {
                        c = str[8];
                        if (c == '-') {
                          c = str[9];
                          if (c == 'p') {
                            c = str[10];
                            if (c == 'a') {
                              c = str[11];
                              if (c == 'g') {
                                c = str[12];
                                if (c == 'e') {
                                  c = str[13];
                                  if (!c) return NEW_SRV_ACTION_CONTESTS_PAGE;
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      } else if (c < 's') {
                        if (c == '-') {
                          c = str[8];
                          if (c == 'i') {
                            c = str[9];
                            if (c == 'n') {
                              c = str[10];
                              if (c == 'f') {
                                c = str[11];
                                if (c == 'o') {
                                  c = str[12];
                                  if (c == '-') {
                                    c = str[13];
                                    if (c == 'j') {
                                      c = str[14];
                                      if (c == 's') {
                                        c = str[15];
                                        if (c == 'o') {
                                          c = str[16];
                                          if (c == 'n') {
                                            c = str[17];
                                            if (!c) return NEW_SRV_ACTION_CONTEST_INFO_JSON;
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 'i') {
                            if (c == 'b') {
                              c = str[9];
                              if (c == 'a') {
                                c = str[10];
                                if (c == 't') {
                                  c = str[11];
                                  if (c == 'c') {
                                    c = str[12];
                                    if (c == 'h') {
                                      c = str[13];
                                      if (!c) return NEW_SRV_ACTION_CONTEST_BATCH;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          } else {
                            if (c == 's') {
                              c = str[9];
                              if (c == 't') {
                                c = str[10];
                                if (c == 'a') {
                                  c = str[11];
                                  if (c == 't') {
                                    c = str[12];
                                    if (c == 'u') {
                                      c = str[13];
                                      if (c == 's') {
                                        c = str[14];
                                        if (c == '-') {
                                          c = str[15];
                                          if (c == 'j') {
                                            c = str[16];
                                            if (c == 's') {
                                              c = str[17];
                                              if (c == 'o') {
                                                c = str[18];
                                                if (c == 'n') {
                                                  c = str[19];
                                                  if (!c) return NEW_SRV_ACTION_CONTEST_STATUS_JSON;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          }
                          return 0;
                        }
                      } else {
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
              } else {
              }
              return 0;
            } else if (c < 't') {
              if (c == 'f') {
                c = str[4];
                if (c == 'i') {
                  c = str[5];
                  if (c == 'r') {
                    c = str[6];
                    if (c == 'm') {
                      c = str[7];
                      if (c == '-') {
                        c = str[8];
                        if (c == 'a') {
                          c = str[9];
                          if (c == 'v') {
                            c = str[10];
                            if (c == 'a') {
                              c = str[11];
                              if (c == 't') {
                                c = str[12];
                                if (c == 'a') {
                                  c = str[13];
                                  if (c == 'r') {
                                    c = str[14];
                                    if (!c) return NEW_SRV_ACTION_CONFIRM_AVATAR;
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
            } else {
            }
            return 0;
          } else if (c < 'n') {
            if (c == 'm') {
              c = str[3];
              if (c == 'p') {
                c = str[4];
                if (c == 'i') {
                  c = str[5];
                  if (c == 'l') {
                    c = str[6];
                    if (c == 'e') {
                      c = str[7];
                      if (c == 'r') {
                        c = str[8];
                        if (c == '-') {
                          c = str[9];
                          if (c == 'o') {
                            c = str[10];
                            if (c == 'p') {
                              c = str[11];
                              if (!c) return NEW_SRV_ACTION_COMPILER_OP;
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                } else if (c < 'i') {
                  if (c == 'a') {
                    c = str[5];
                    if (c == 'r') {
                      c = str[6];
                      if (c == 'e') {
                        c = str[7];
                        if (c == '-') {
                          c = str[8];
                          if (c == 'r') {
                            c = str[9];
                            if (c == 'u') {
                              c = str[10];
                              if (c == 'n') {
                                c = str[11];
                                if (c == 's') {
                                  c = str[12];
                                  if (!c) return NEW_SRV_ACTION_COMPARE_RUNS;
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                } else {
                }
                return 0;
              }
              return 0;
            }
          } else {
            if (c == 'o') {
              c = str[3];
              if (c == 'k') {
                c = str[4];
                if (c == 'i') {
                  c = str[5];
                  if (c == 'e') {
                    c = str[6];
                    if (c == '-') {
                      c = str[7];
                      if (c == 'l') {
                        c = str[8];
                        if (c == 'o') {
                          c = str[9];
                          if (c == 'g') {
                            c = str[10];
                            if (c == 'i') {
                              c = str[11];
                              if (c == 'n') {
                                c = str[12];
                                if (!c) return NEW_SRV_ACTION_COOKIE_LOGIN;
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
          }
          return 0;
        } else if (c < 'o') {
          if (c == 'l') {
            c = str[2];
            if (c == 'e') {
              c = str[3];
              if (c == 'a') {
                c = str[4];
                if (c == 'r') {
                  c = str[5];
                  if (c == '-') {
                    c = str[6];
                    if (c == 'r') {
                      c = str[7];
                      if (c == 'u') {
                        c = str[8];
                        if (c == 'n') {
                          c = str[9];
                          if (!c) return NEW_SRV_ACTION_CLEAR_RUN;
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    } else if (c < 'r') {
                      if (c == 'p') {
                        c = str[7];
                        if (c == 'a') {
                          c = str[8];
                          if (c == 's') {
                            c = str[9];
                            if (c == 's') {
                              c = str[10];
                              if (c == 'w') {
                                c = str[11];
                                if (c == 'o') {
                                  c = str[12];
                                  if (c == 'r') {
                                    c = str[13];
                                    if (c == 'd') {
                                      c = str[14];
                                      if (c == 's') {
                                        c = str[15];
                                        if (c == '-') {
                                          c = str[16];
                                          if (c == '2') {
                                            c = str[17];
                                            if (!c) return NEW_SRV_ACTION_CLEAR_PASSWORDS_2;
                                            return 0;
                                          } else if (c < '2') {
                                            if (c == '1') {
                                              c = str[17];
                                              if (!c) return NEW_SRV_ACTION_CLEAR_PASSWORDS_1;
                                              return 0;
                                            }
                                          } else {
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      } else if (c < 'p') {
                        if (c == 'd') {
                          c = str[7];
                          if (c == 'i') {
                            c = str[8];
                            if (c == 's') {
                              c = str[9];
                              if (c == 'q') {
                                c = str[10];
                                if (c == 'u') {
                                  c = str[11];
                                  if (c == 'a') {
                                    c = str[12];
                                    if (c == 'l') {
                                      c = str[13];
                                      if (c == 'i') {
                                        c = str[14];
                                        if (c == 'f') {
                                          c = str[15];
                                          if (c == 'i') {
                                            c = str[16];
                                            if (c == 'c') {
                                              c = str[17];
                                              if (c == 'a') {
                                                c = str[18];
                                                if (c == 't') {
                                                  c = str[19];
                                                  if (c == 'i') {
                                                    c = str[20];
                                                    if (c == 'o') {
                                                      c = str[21];
                                                      if (c == 'n') {
                                                        c = str[22];
                                                        if (!c) return NEW_SRV_ACTION_CLEAR_DISQUALIFICATION;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              } else if (c < 'q') {
                                if (c == 'p') {
                                  c = str[10];
                                  if (c == 'l') {
                                    c = str[11];
                                    if (c == 'a') {
                                      c = str[12];
                                      if (c == 'y') {
                                        c = str[13];
                                        if (c == 'e') {
                                          c = str[14];
                                          if (c == 'd') {
                                            c = str[15];
                                            if (c == '-') {
                                              c = str[16];
                                              if (c == '2') {
                                                c = str[17];
                                                if (!c) return NEW_SRV_ACTION_CLEAR_DISPLAYED_2;
                                                return 0;
                                              } else if (c < '2') {
                                                if (c == '1') {
                                                  c = str[17];
                                                  if (!c) return NEW_SRV_ACTION_CLEAR_DISPLAYED_1;
                                                  return 0;
                                                }
                                              } else {
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                              } else {
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                      } else {
                      }
                    } else {
                      if (c == 't') {
                        c = str[7];
                        if (c == 'e') {
                          c = str[8];
                          if (c == 's') {
                            c = str[9];
                            if (c == 't') {
                              c = str[10];
                              if (c == 'i') {
                                c = str[11];
                                if (c == 'n') {
                                  c = str[12];
                                  if (c == 'g') {
                                    c = str[13];
                                    if (c == '-') {
                                      c = str[14];
                                      if (c == 'f') {
                                        c = str[15];
                                        if (c == 'i') {
                                          c = str[16];
                                          if (c == 'n') {
                                            c = str[17];
                                            if (c == 'i') {
                                              c = str[18];
                                              if (c == 's') {
                                                c = str[19];
                                                if (c == 'h') {
                                                  c = str[20];
                                                  if (c == 'e') {
                                                    c = str[21];
                                                    if (c == 'd') {
                                                      c = str[22];
                                                      if (c == '-') {
                                                        c = str[23];
                                                        if (c == 'f') {
                                                          c = str[24];
                                                          if (c == 'l') {
                                                            c = str[25];
                                                            if (c == 'a') {
                                                              c = str[26];
                                                              if (c == 'g') {
                                                                c = str[27];
                                                                if (!c) return NEW_SRV_ACTION_CLEAR_TESTING_FINISHED_FLAG;
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      } else if (c < 't') {
                        if (c == 's') {
                          c = str[7];
                          if (c == 'e') {
                            c = str[8];
                            if (c == 's') {
                              c = str[9];
                              if (c == 's') {
                                c = str[10];
                                if (c == 'i') {
                                  c = str[11];
                                  if (c == 'o') {
                                    c = str[12];
                                    if (c == 'n') {
                                      c = str[13];
                                      if (c == '-') {
                                        c = str[14];
                                        if (c == 'c') {
                                          c = str[15];
                                          if (c == 'a') {
                                            c = str[16];
                                            if (c == 'c') {
                                              c = str[17];
                                              if (c == 'h') {
                                                c = str[18];
                                                if (c == 'e') {
                                                  c = str[19];
                                                  if (!c) return NEW_SRV_ACTION_CLEAR_SESSION_CACHE;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                      } else {
                      }
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            } else if (c < 'e') {
              if (c == 'a') {
                c = str[3];
                if (c == 'r') {
                  c = str[4];
                  if (c == '-') {
                    c = str[5];
                    if (c == 'r') {
                      c = str[6];
                      if (c == 'e') {
                        c = str[7];
                        if (c == 'p') {
                          c = str[8];
                          if (c == 'l') {
                            c = str[9];
                            if (c == 'y') {
                              c = str[10];
                              if (!c) return NEW_SRV_ACTION_CLAR_REPLY;
                              if (c == '-') {
                                c = str[11];
                                if (c == 'r') {
                                  c = str[12];
                                  if (c == 'e') {
                                    c = str[13];
                                    if (c == 'a') {
                                      c = str[14];
                                      if (c == 'd') {
                                        c = str[15];
                                        if (c == '-') {
                                          c = str[16];
                                          if (c == 'p') {
                                            c = str[17];
                                            if (c == 'r') {
                                              c = str[18];
                                              if (c == 'o') {
                                                c = str[19];
                                                if (c == 'b') {
                                                  c = str[20];
                                                  if (c == 'l') {
                                                    c = str[21];
                                                    if (c == 'e') {
                                                      c = str[22];
                                                      if (c == 'm') {
                                                        c = str[23];
                                                        if (!c) return NEW_SRV_ACTION_CLAR_REPLY_READ_PROBLEM;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                } else if (c < 'r') {
                                  if (c == 'n') {
                                    c = str[12];
                                    if (c == 'o') {
                                      c = str[13];
                                      if (!c) return NEW_SRV_ACTION_CLAR_REPLY_NO;
                                      if (c == '-') {
                                        c = str[14];
                                        if (c == 'c') {
                                          c = str[15];
                                          if (c == 'o') {
                                            c = str[16];
                                            if (c == 'm') {
                                              c = str[17];
                                              if (c == 'm') {
                                                c = str[18];
                                                if (c == 'e') {
                                                  c = str[19];
                                                  if (c == 'n') {
                                                    c = str[20];
                                                    if (c == 't') {
                                                      c = str[21];
                                                      if (c == 's') {
                                                        c = str[22];
                                                        if (!c) return NEW_SRV_ACTION_CLAR_REPLY_NO_COMMENTS;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  } else if (c < 'n') {
                                    if (c == 'a') {
                                      c = str[12];
                                      if (c == 'l') {
                                        c = str[13];
                                        if (c == 'l') {
                                          c = str[14];
                                          if (!c) return NEW_SRV_ACTION_CLAR_REPLY_ALL;
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                  } else {
                                  }
                                } else {
                                  if (c == 'y') {
                                    c = str[12];
                                    if (c == 'e') {
                                      c = str[13];
                                      if (c == 's') {
                                        c = str[14];
                                        if (!c) return NEW_SRV_ACTION_CLAR_REPLY_YES;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
            } else {
            }
            return 0;
          } else if (c < 'l') {
            if (c == 'h') {
              c = str[2];
              if (c == 'a') {
                c = str[3];
                if (c == 'n') {
                  c = str[4];
                  if (c == 'g') {
                    c = str[5];
                    if (c == 'e') {
                      c = str[6];
                      if (c == '-') {
                        c = str[7];
                        if (c == 'p') {
                          c = str[8];
                          if (c == 'a') {
                            c = str[9];
                            if (c == 's') {
                              c = str[10];
                              if (c == 's') {
                                c = str[11];
                                if (c == 'w') {
                                  c = str[12];
                                  if (c == 'o') {
                                    c = str[13];
                                    if (c == 'r') {
                                      c = str[14];
                                      if (c == 'd') {
                                        c = str[15];
                                        if (!c) return NEW_SRV_ACTION_CHANGE_PASSWORD;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 'p') {
                          if (c == 'f') {
                            c = str[8];
                            if (c == 'i') {
                              c = str[9];
                              if (c == 'n') {
                                c = str[10];
                                if (c == 'i') {
                                  c = str[11];
                                  if (c == 's') {
                                    c = str[12];
                                    if (c == 'h') {
                                      c = str[13];
                                      if (c == '-') {
                                        c = str[14];
                                        if (c == 't') {
                                          c = str[15];
                                          if (c == 'i') {
                                            c = str[16];
                                            if (c == 'm') {
                                              c = str[17];
                                              if (c == 'e') {
                                                c = str[18];
                                                if (!c) return NEW_SRV_ACTION_CHANGE_FINISH_TIME;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 'f') {
                            if (c == 'd') {
                              c = str[8];
                              if (c == 'u') {
                                c = str[9];
                                if (c == 'r') {
                                  c = str[10];
                                  if (c == 'a') {
                                    c = str[11];
                                    if (c == 't') {
                                      c = str[12];
                                      if (c == 'i') {
                                        c = str[13];
                                        if (c == 'o') {
                                          c = str[14];
                                          if (c == 'n') {
                                            c = str[15];
                                            if (!c) return NEW_SRV_ACTION_CHANGE_DURATION;
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          } else {
                            if (c == 'l') {
                              c = str[8];
                              if (c == 'a') {
                                c = str[9];
                                if (c == 'n') {
                                  c = str[10];
                                  if (c == 'g') {
                                    c = str[11];
                                    if (c == 'u') {
                                      c = str[12];
                                      if (c == 'a') {
                                        c = str[13];
                                        if (c == 'g') {
                                          c = str[14];
                                          if (c == 'e') {
                                            c = str[15];
                                            if (!c) return NEW_SRV_ACTION_CHANGE_LANGUAGE;
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          }
                        } else {
                          if (c == 's') {
                            c = str[8];
                            if (c == 't') {
                              c = str[9];
                              if (c == 'a') {
                                c = str[10];
                                if (c == 't') {
                                  c = str[11];
                                  if (c == 'u') {
                                    c = str[12];
                                    if (c == 's') {
                                      c = str[13];
                                      if (!c) return NEW_SRV_ACTION_CHANGE_STATUS;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 's') {
                            if (c == 'r') {
                              c = str[8];
                              if (c == 'u') {
                                c = str[9];
                                if (c == 'n') {
                                  c = str[10];
                                  if (c == '-') {
                                    c = str[11];
                                    if (c == 's') {
                                      c = str[12];
                                      if (c == 't') {
                                        c = str[13];
                                        if (c == 'a') {
                                          c = str[14];
                                          if (c == 't') {
                                            c = str[15];
                                            if (c == 'u') {
                                              c = str[16];
                                              if (c == 's') {
                                                c = str[17];
                                                if (!c) return NEW_SRV_ACTION_CHANGE_RUN_STATUS;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      } else if (c < 't') {
                                        if (c == 'c') {
                                          c = str[13];
                                          if (c == 'o') {
                                            c = str[14];
                                            if (c == 'r') {
                                              c = str[15];
                                              if (c == 'e') {
                                                c = str[16];
                                                if (!c) return NEW_SRV_ACTION_CHANGE_RUN_SCORE;
                                                if (c == '-') {
                                                  c = str[17];
                                                  if (c == 'a') {
                                                    c = str[18];
                                                    if (c == 'd') {
                                                      c = str[19];
                                                      if (c == 'j') {
                                                        c = str[20];
                                                        if (!c) return NEW_SRV_ACTION_CHANGE_RUN_SCORE_ADJ;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                      } else {
                                      }
                                      return 0;
                                    } else if (c < 's') {
                                      if (c == 'l') {
                                        c = str[12];
                                        if (c == 'a') {
                                          c = str[13];
                                          if (c == 'n') {
                                            c = str[14];
                                            if (c == 'g') {
                                              c = str[15];
                                              if (c == '-') {
                                                c = str[16];
                                                if (c == 'i') {
                                                  c = str[17];
                                                  if (c == 'd') {
                                                    c = str[18];
                                                    if (!c) return NEW_SRV_ACTION_CHANGE_RUN_LANG_ID;
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      } else if (c < 'l') {
                                        if (c == 'i') {
                                          c = str[12];
                                          if (c == 's') {
                                            c = str[13];
                                            if (c == '-') {
                                              c = str[14];
                                              if (c == 'm') {
                                                c = str[15];
                                                if (c == 'a') {
                                                  c = str[16];
                                                  if (c == 'r') {
                                                    c = str[17];
                                                    if (c == 'k') {
                                                      c = str[18];
                                                      if (c == 'e') {
                                                        c = str[19];
                                                        if (c == 'd') {
                                                          c = str[20];
                                                          if (!c) return NEW_SRV_ACTION_CHANGE_RUN_IS_MARKED;
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              } else if (c < 'm') {
                                                if (c == 'h') {
                                                  c = str[15];
                                                  if (c == 'i') {
                                                    c = str[16];
                                                    if (c == 'd') {
                                                      c = str[17];
                                                      if (c == 'd') {
                                                        c = str[18];
                                                        if (c == 'e') {
                                                          c = str[19];
                                                          if (c == 'n') {
                                                            c = str[20];
                                                            if (!c) return NEW_SRV_ACTION_CHANGE_RUN_IS_HIDDEN;
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                } else if (c < 'h') {
                                                  if (c == 'e') {
                                                    c = str[15];
                                                    if (c == 'x') {
                                                      c = str[16];
                                                      if (c == 'a') {
                                                        c = str[17];
                                                        if (c == 'm') {
                                                          c = str[18];
                                                          if (c == 'i') {
                                                            c = str[19];
                                                            if (c == 'n') {
                                                              c = str[20];
                                                              if (c == 'a') {
                                                                c = str[21];
                                                                if (c == 'b') {
                                                                  c = str[22];
                                                                  if (c == 'l') {
                                                                    c = str[23];
                                                                    if (c == 'e') {
                                                                      c = str[24];
                                                                      if (!c) return NEW_SRV_ACTION_CHANGE_RUN_IS_EXAMINABLE;
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                } else {
                                                  if (c == 'i') {
                                                    c = str[15];
                                                    if (c == 'm') {
                                                      c = str[16];
                                                      if (c == 'p') {
                                                        c = str[17];
                                                        if (c == 'o') {
                                                          c = str[18];
                                                          if (c == 'r') {
                                                            c = str[19];
                                                            if (c == 't') {
                                                              c = str[20];
                                                              if (c == 'e') {
                                                                c = str[21];
                                                                if (c == 'd') {
                                                                  c = str[22];
                                                                  if (!c) return NEW_SRV_ACTION_CHANGE_RUN_IS_IMPORTED;
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                }
                                              } else {
                                                if (c == 's') {
                                                  c = str[15];
                                                  if (c == 'a') {
                                                    c = str[16];
                                                    if (c == 'v') {
                                                      c = str[17];
                                                      if (c == 'e') {
                                                        c = str[18];
                                                        if (c == 'd') {
                                                          c = str[19];
                                                          if (!c) return NEW_SRV_ACTION_CHANGE_RUN_IS_SAVED;
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                } else if (c < 's') {
                                                  if (c == 'r') {
                                                    c = str[15];
                                                    if (c == 'e') {
                                                      c = str[16];
                                                      if (c == 'a') {
                                                        c = str[17];
                                                        if (c == 'd') {
                                                          c = str[18];
                                                          if (c == 'o') {
                                                            c = str[19];
                                                            if (c == 'n') {
                                                              c = str[20];
                                                              if (c == 'l') {
                                                                c = str[21];
                                                                if (c == 'y') {
                                                                  c = str[22];
                                                                  if (!c) return NEW_SRV_ACTION_CHANGE_RUN_IS_READONLY;
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                } else {
                                                }
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        } else if (c < 'i') {
                                          if (c == 'f') {
                                            c = str[12];
                                            if (c == 'i') {
                                              c = str[13];
                                              if (c == 'e') {
                                                c = str[14];
                                                if (c == 'l') {
                                                  c = str[15];
                                                  if (c == 'd') {
                                                    c = str[16];
                                                    if (c == 's') {
                                                      c = str[17];
                                                      if (!c) return NEW_SRV_ACTION_CHANGE_RUN_FIELDS;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                        } else {
                                        }
                                      } else {
                                        if (c == 'p') {
                                          c = str[12];
                                          if (c == 'r') {
                                            c = str[13];
                                            if (c == 'o') {
                                              c = str[14];
                                              if (c == 'b') {
                                                c = str[15];
                                                if (c == '-') {
                                                  c = str[16];
                                                  if (c == 'i') {
                                                    c = str[17];
                                                    if (c == 'd') {
                                                      c = str[18];
                                                      if (!c) return NEW_SRV_ACTION_CHANGE_RUN_PROB_ID;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          } else if (c < 'r') {
                                            if (c == 'a') {
                                              c = str[13];
                                              if (c == 'g') {
                                                c = str[14];
                                                if (c == 'e') {
                                                  c = str[15];
                                                  if (c == 's') {
                                                    c = str[16];
                                                    if (!c) return NEW_SRV_ACTION_CHANGE_RUN_PAGES;
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                          } else {
                                          }
                                          return 0;
                                        }
                                      }
                                    } else {
                                      if (c == 'u') {
                                        c = str[12];
                                        if (c == 's') {
                                          c = str[13];
                                          if (c == 'e') {
                                            c = str[14];
                                            if (c == 'r') {
                                              c = str[15];
                                              if (c == '-') {
                                                c = str[16];
                                                if (c == 'l') {
                                                  c = str[17];
                                                  if (c == 'o') {
                                                    c = str[18];
                                                    if (c == 'g') {
                                                      c = str[19];
                                                      if (c == 'i') {
                                                        c = str[20];
                                                        if (c == 'n') {
                                                          c = str[21];
                                                          if (!c) return NEW_SRV_ACTION_CHANGE_RUN_USER_LOGIN;
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                } else if (c < 'l') {
                                                  if (c == 'i') {
                                                    c = str[17];
                                                    if (c == 'd') {
                                                      c = str[18];
                                                      if (!c) return NEW_SRV_ACTION_CHANGE_RUN_USER_ID;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                } else {
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      } else if (c < 'u') {
                                        if (c == 't') {
                                          c = str[12];
                                          if (c == 'e') {
                                            c = str[13];
                                            if (c == 's') {
                                              c = str[14];
                                              if (c == 't') {
                                                c = str[15];
                                                if (!c) return NEW_SRV_ACTION_CHANGE_RUN_TEST;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                      } else {
                                        if (c == 'v') {
                                          c = str[12];
                                          if (c == 'a') {
                                            c = str[13];
                                            if (c == 'r') {
                                              c = str[14];
                                              if (c == 'i') {
                                                c = str[15];
                                                if (c == 'a') {
                                                  c = str[16];
                                                  if (c == 'n') {
                                                    c = str[17];
                                                    if (c == 't') {
                                                      c = str[18];
                                                      if (!c) return NEW_SRV_ACTION_CHANGE_RUN_VARIANT;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                      }
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          } else {
                          }
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
          } else {
          }
        } else {
          if (c == 'r') {
            c = str[2];
            if (c == 'o') {
              c = str[3];
              if (c == 'p') {
                c = str[4];
                if (c == '-') {
                  c = str[5];
                  if (c == 'a') {
                    c = str[6];
                    if (c == 'v') {
                      c = str[7];
                      if (c == 'a') {
                        c = str[8];
                        if (c == 't') {
                          c = str[9];
                          if (c == 'a') {
                            c = str[10];
                            if (c == 'r') {
                              c = str[11];
                              if (c == '-') {
                                c = str[12];
                                if (c == 'p') {
                                  c = str[13];
                                  if (c == 'a') {
                                    c = str[14];
                                    if (c == 'g') {
                                      c = str[15];
                                      if (c == 'e') {
                                        c = str[16];
                                        if (!c) return NEW_SRV_ACTION_CROP_AVATAR_PAGE;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            } else if (c < 'o') {
              if (c == 'e') {
                c = str[3];
                if (c == 'a') {
                  c = str[4];
                  if (c == 't') {
                    c = str[5];
                    if (c == 'e') {
                      c = str[6];
                      if (c == '-') {
                        c = str[7];
                        if (c == 'u') {
                          c = str[8];
                          if (c == 's') {
                            c = str[9];
                            if (c == 'e') {
                              c = str[10];
                              if (c == 'r') {
                                c = str[11];
                                if (c == 'p') {
                                  c = str[12];
                                  if (c == 'r') {
                                    c = str[13];
                                    if (c == 'o') {
                                      c = str[14];
                                      if (c == 'b') {
                                        c = str[15];
                                        if (!c) return NEW_SRV_ACTION_CREATE_USERPROB;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 'u') {
                          if (c == 'a') {
                            c = str[8];
                            if (c == 'p') {
                              c = str[9];
                              if (c == 'i') {
                                c = str[10];
                                if (c == '-') {
                                  c = str[11];
                                  if (c == 'k') {
                                    c = str[12];
                                    if (c == 'e') {
                                      c = str[13];
                                      if (c == 'y') {
                                        c = str[14];
                                        if (!c) return NEW_SRV_ACTION_CREATE_API_KEY;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                        } else {
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
            } else {
            }
            return 0;
          }
        }
        return 0;
      } else if (c < 'c') {
        if (c == 'a') {
          c = str[1];
          if (c == 'p') {
            c = str[2];
            if (c == 'i') {
              c = str[3];
              if (c == '-') {
                c = str[4];
                if (c == 'k') {
                  c = str[5];
                  if (c == 'e') {
                    c = str[6];
                    if (c == 'y') {
                      c = str[7];
                      if (c == 's') {
                        c = str[8];
                        if (c == '-') {
                          c = str[9];
                          if (c == 'p') {
                            c = str[10];
                            if (c == 'a') {
                              c = str[11];
                              if (c == 'g') {
                                c = str[12];
                                if (c == 'e') {
                                  c = str[13];
                                  if (!c) return NEW_SRV_ACTION_API_KEYS_PAGE;
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          } else if (c < 'p') {
            if (c == 'd') {
              c = str[2];
              if (c == 'm') {
                c = str[3];
                if (c == 'i') {
                  c = str[4];
                  if (c == 'n') {
                    c = str[5];
                    if (c == '-') {
                      c = str[6];
                      if (c == 'c') {
                        c = str[7];
                        if (c == 'o') {
                          c = str[8];
                          if (c == 'n') {
                            c = str[9];
                            if (c == 't') {
                              c = str[10];
                              if (c == 'e') {
                                c = str[11];
                                if (c == 's') {
                                  c = str[12];
                                  if (c == 't') {
                                    c = str[13];
                                    if (c == '-') {
                                      c = str[14];
                                      if (c == 's') {
                                        c = str[15];
                                        if (c == 'e') {
                                          c = str[16];
                                          if (c == 't') {
                                            c = str[17];
                                            if (c == 't') {
                                              c = str[18];
                                              if (c == 'i') {
                                                c = str[19];
                                                if (c == 'n') {
                                                  c = str[20];
                                                  if (c == 'g') {
                                                    c = str[21];
                                                    if (c == 's') {
                                                      c = str[22];
                                                      if (!c) return NEW_SRV_ACTION_ADMIN_CONTEST_SETTINGS;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 'o') {
                          if (c == 'h') {
                            c = str[8];
                            if (c == 'a') {
                              c = str[9];
                              if (c == 'n') {
                                c = str[10];
                                if (c == 'g') {
                                  c = str[11];
                                  if (c == 'e') {
                                    c = str[12];
                                    if (c == '-') {
                                      c = str[13];
                                      if (c == 'o') {
                                        c = str[14];
                                        if (c == 'n') {
                                          c = str[15];
                                          if (c == 'l') {
                                            c = str[16];
                                            if (c == 'i') {
                                              c = str[17];
                                              if (c == 'n') {
                                                c = str[18];
                                                if (c == 'e') {
                                                  c = str[19];
                                                  if (c == '-') {
                                                    c = str[20];
                                                    if (c == 'v') {
                                                      c = str[21];
                                                      if (c == 'i') {
                                                        c = str[22];
                                                        if (c == 'e') {
                                                          c = str[23];
                                                          if (c == 'w') {
                                                            c = str[24];
                                                            if (c == '-') {
                                                              c = str[25];
                                                              if (c == 'r') {
                                                                c = str[26];
                                                                if (c == 'e') {
                                                                  c = str[27];
                                                                  if (c == 'p') {
                                                                    c = str[28];
                                                                    if (c == 'o') {
                                                                      c = str[29];
                                                                      if (c == 'r') {
                                                                        c = str[30];
                                                                        if (c == 't') {
                                                                          c = str[31];
                                                                          if (!c) return NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_REPORT;
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              } else if (c < 'r') {
                                                                if (c == 'j') {
                                                                  c = str[26];
                                                                  if (c == 'u') {
                                                                    c = str[27];
                                                                    if (c == 'd') {
                                                                      c = str[28];
                                                                      if (c == 'g') {
                                                                        c = str[29];
                                                                        if (c == 'e') {
                                                                          c = str[30];
                                                                          if (c == '-') {
                                                                            c = str[31];
                                                                            if (c == 's') {
                                                                              c = str[32];
                                                                              if (c == 'c') {
                                                                                c = str[33];
                                                                                if (c == 'o') {
                                                                                  c = str[34];
                                                                                  if (c == 'r') {
                                                                                    c = str[35];
                                                                                    if (c == 'e') {
                                                                                      c = str[36];
                                                                                      if (!c) return NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_JUDGE_SCORE;
                                                                                      return 0;
                                                                                    }
                                                                                    return 0;
                                                                                  }
                                                                                  return 0;
                                                                                }
                                                                                return 0;
                                                                              }
                                                                              return 0;
                                                                            }
                                                                            return 0;
                                                                          }
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                              } else {
                                                                if (c == 's') {
                                                                  c = str[26];
                                                                  if (c == 'o') {
                                                                    c = str[27];
                                                                    if (c == 'u') {
                                                                      c = str[28];
                                                                      if (c == 'r') {
                                                                        c = str[29];
                                                                        if (c == 'c') {
                                                                          c = str[30];
                                                                          if (c == 'e') {
                                                                            c = str[31];
                                                                            if (!c) return NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_SOURCE;
                                                                            return 0;
                                                                          }
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      } else if (c < 'i') {
                                                        if (c == 'a') {
                                                          c = str[22];
                                                          if (c == 'l') {
                                                            c = str[23];
                                                            if (c == 'u') {
                                                              c = str[24];
                                                              if (c == 'e') {
                                                                c = str[25];
                                                                if (c == 'r') {
                                                                  c = str[26];
                                                                  if (c == '-') {
                                                                    c = str[27];
                                                                    if (c == 'j') {
                                                                      c = str[28];
                                                                      if (c == 'u') {
                                                                        c = str[29];
                                                                        if (c == 'd') {
                                                                          c = str[30];
                                                                          if (c == 'g') {
                                                                            c = str[31];
                                                                            if (c == 'e') {
                                                                              c = str[32];
                                                                              if (c == '-') {
                                                                                c = str[33];
                                                                                if (c == 'c') {
                                                                                  c = str[34];
                                                                                  if (c == 'o') {
                                                                                    c = str[35];
                                                                                    if (c == 'm') {
                                                                                      c = str[36];
                                                                                      if (c == 'm') {
                                                                                        c = str[37];
                                                                                        if (c == 'e') {
                                                                                          c = str[38];
                                                                                          if (c == 'n') {
                                                                                            c = str[39];
                                                                                            if (c == 't') {
                                                                                              c = str[40];
                                                                                              if (c == 's') {
                                                                                                c = str[41];
                                                                                                if (!c) return NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VALUER_JUDGE_COMMENTS;
                                                                                                return 0;
                                                                                              }
                                                                                              return 0;
                                                                                            }
                                                                                            return 0;
                                                                                          }
                                                                                          return 0;
                                                                                        }
                                                                                        return 0;
                                                                                      }
                                                                                      return 0;
                                                                                    }
                                                                                    return 0;
                                                                                  }
                                                                                  return 0;
                                                                                }
                                                                                return 0;
                                                                              }
                                                                              return 0;
                                                                            }
                                                                            return 0;
                                                                          }
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                      } else {
                                                      }
                                                      return 0;
                                                    } else if (c < 'v') {
                                                      if (c == 'f') {
                                                        c = str[21];
                                                        if (c == 'i') {
                                                          c = str[22];
                                                          if (c == 'n') {
                                                            c = str[23];
                                                            if (c == 'a') {
                                                              c = str[24];
                                                              if (c == 'l') {
                                                                c = str[25];
                                                                if (c == '-') {
                                                                  c = str[26];
                                                                  if (c == 'v') {
                                                                    c = str[27];
                                                                    if (c == 'i') {
                                                                      c = str[28];
                                                                      if (c == 's') {
                                                                        c = str[29];
                                                                        if (c == 'i') {
                                                                          c = str[30];
                                                                          if (c == 'b') {
                                                                            c = str[31];
                                                                            if (c == 'i') {
                                                                              c = str[32];
                                                                              if (c == 'l') {
                                                                                c = str[33];
                                                                                if (c == 'i') {
                                                                                  c = str[34];
                                                                                  if (c == 't') {
                                                                                    c = str[35];
                                                                                    if (c == 'y') {
                                                                                      c = str[36];
                                                                                      if (!c) return NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_FINAL_VISIBILITY;
                                                                                      return 0;
                                                                                    }
                                                                                    return 0;
                                                                                  }
                                                                                  return 0;
                                                                                }
                                                                                return 0;
                                                                              }
                                                                              return 0;
                                                                            }
                                                                            return 0;
                                                                          }
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                    } else {
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                        } else {
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              } else if (c < 'm') {
                if (c == 'd') {
                  c = str[3];
                  if (c == '-') {
                    c = str[4];
                    if (c == 'r') {
                      c = str[5];
                      if (c == 'e') {
                        c = str[6];
                        if (c == 'v') {
                          c = str[7];
                          if (c == 'i') {
                            c = str[8];
                            if (c == 'e') {
                              c = str[9];
                              if (c == 'w') {
                                c = str[10];
                                if (c == '-') {
                                  c = str[11];
                                  if (c == 'c') {
                                    c = str[12];
                                    if (c == 'o') {
                                      c = str[13];
                                      if (c == 'm') {
                                        c = str[14];
                                        if (c == 'm') {
                                          c = str[15];
                                          if (c == 'e') {
                                            c = str[16];
                                            if (c == 'n') {
                                              c = str[17];
                                              if (c == 't') {
                                                c = str[18];
                                                if (!c) return NEW_SRV_ACTION_ADD_REVIEW_COMMENT;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
              } else {
              }
              return 0;
            }
          } else {
            if (c == 's') {
              c = str[2];
              if (c == 's') {
                c = str[3];
                if (c == 'i') {
                  c = str[4];
                  if (c == 'g') {
                    c = str[5];
                    if (c == 'n') {
                      c = str[6];
                      if (c == '-') {
                        c = str[7];
                        if (c == 'e') {
                          c = str[8];
                          if (c == 'x') {
                            c = str[9];
                            if (c == 'a') {
                              c = str[10];
                              if (c == 'm') {
                                c = str[11];
                                if (c == 'i') {
                                  c = str[12];
                                  if (c == 'n') {
                                    c = str[13];
                                    if (c == 'e') {
                                      c = str[14];
                                      if (c == 'r') {
                                        c = str[15];
                                        if (!c) return NEW_SRV_ACTION_ASSIGN_EXAMINER;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 'e') {
                          if (c == 'c') {
                            c = str[8];
                            if (c == 'y') {
                              c = str[9];
                              if (c == 'p') {
                                c = str[10];
                                if (c == 'h') {
                                  c = str[11];
                                  if (c == 'e') {
                                    c = str[12];
                                    if (c == 'r') {
                                      c = str[13];
                                      if (c == 's') {
                                        c = str[14];
                                        if (c == '-') {
                                          c = str[15];
                                          if (c == '2') {
                                            c = str[16];
                                            if (!c) return NEW_SRV_ACTION_ASSIGN_CYPHERS_2;
                                            return 0;
                                          } else if (c < '2') {
                                            if (c == '1') {
                                              c = str[16];
                                              if (!c) return NEW_SRV_ACTION_ASSIGN_CYPHERS_1;
                                              return 0;
                                            }
                                          } else {
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            } else if (c < 'y') {
                              if (c == 'h') {
                                c = str[9];
                                if (c == 'i') {
                                  c = str[10];
                                  if (c == 'e') {
                                    c = str[11];
                                    if (c == 'f') {
                                      c = str[12];
                                      if (c == '-') {
                                        c = str[13];
                                        if (c == 'e') {
                                          c = str[14];
                                          if (c == 'x') {
                                            c = str[15];
                                            if (c == 'a') {
                                              c = str[16];
                                              if (c == 'm') {
                                                c = str[17];
                                                if (c == 'i') {
                                                  c = str[18];
                                                  if (c == 'n') {
                                                    c = str[19];
                                                    if (c == 'e') {
                                                      c = str[20];
                                                      if (c == 'r') {
                                                        c = str[21];
                                                        if (!c) return NEW_SRV_ACTION_ASSIGN_CHIEF_EXAMINER;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                            } else {
                            }
                            return 0;
                          }
                        } else {
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
          }
          return 0;
        } else if (c < 'a') {
          if (c == '0') {
            c = str[1];
            if (!c) return 0;
            return 0;
          }
        } else {
        }
      } else {
        if (c == 'e') {
          c = str[1];
          if (c == 'x') {
            c = str[2];
            if (c == 'p') {
              c = str[3];
              if (c == 'o') {
                c = str[4];
                if (c == 'r') {
                  c = str[5];
                  if (c == 't') {
                    c = str[6];
                    if (c == '-') {
                      c = str[7];
                      if (c == 'x') {
                        c = str[8];
                        if (c == 'm') {
                          c = str[9];
                          if (c == 'l') {
                            c = str[10];
                            if (c == '-') {
                              c = str[11];
                              if (c == 'r') {
                                c = str[12];
                                if (c == 'u') {
                                  c = str[13];
                                  if (c == 'n') {
                                    c = str[14];
                                    if (c == 's') {
                                      c = str[15];
                                      if (!c) return NEW_SRV_ACTION_EXPORT_XML_RUNS;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            } else if (c < 'p') {
              if (c == 'a') {
                c = str[3];
                if (c == 'm') {
                  c = str[4];
                  if (c == 'i') {
                    c = str[5];
                    if (c == 'n') {
                      c = str[6];
                      if (c == 'e') {
                        c = str[7];
                        if (c == 'r') {
                          c = str[8];
                          if (c == 's') {
                            c = str[9];
                            if (c == '-') {
                              c = str[10];
                              if (c == 'p') {
                                c = str[11];
                                if (c == 'a') {
                                  c = str[12];
                                  if (c == 'g') {
                                    c = str[13];
                                    if (c == 'e') {
                                      c = str[14];
                                      if (!c) return NEW_SRV_ACTION_EXAMINERS_PAGE;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
            } else {
            }
            return 0;
          } else if (c < 'x') {
            if (c == 'n') {
              c = str[2];
              if (c == 't') {
                c = str[3];
                if (c == 'e') {
                  c = str[4];
                  if (c == 'r') {
                    c = str[5];
                    if (c == '-') {
                      c = str[6];
                      if (c == 'c') {
                        c = str[7];
                        if (c == 'o') {
                          c = str[8];
                          if (c == 'n') {
                            c = str[9];
                            if (c == 't') {
                              c = str[10];
                              if (c == 'e') {
                                c = str[11];
                                if (c == 's') {
                                  c = str[12];
                                  if (c == 't') {
                                    c = str[13];
                                    if (!c) return NEW_SRV_ACTION_ENTER_CONTEST;
                                    if (c == '-') {
                                      c = str[14];
                                      if (c == 'j') {
                                        c = str[15];
                                        if (c == 's') {
                                          c = str[16];
                                          if (c == 'o') {
                                            c = str[17];
                                            if (c == 'n') {
                                              c = str[18];
                                              if (!c) return NEW_SRV_ACTION_ENTER_CONTEST_JSON;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              } else if (c < 't') {
                if (c == 'a') {
                  c = str[3];
                  if (c == 'b') {
                    c = str[4];
                    if (c == 'l') {
                      c = str[5];
                      if (c == 'e') {
                        c = str[6];
                        if (c == '-') {
                          c = str[7];
                          if (c == 'v') {
                            c = str[8];
                            if (c == 'i') {
                              c = str[9];
                              if (c == 'r') {
                                c = str[10];
                                if (c == 't') {
                                  c = str[11];
                                  if (c == 'u') {
                                    c = str[12];
                                    if (c == 'a') {
                                      c = str[13];
                                      if (c == 'l') {
                                        c = str[14];
                                        if (c == '-') {
                                          c = str[15];
                                          if (c == 's') {
                                            c = str[16];
                                            if (c == 't') {
                                              c = str[17];
                                              if (c == 'a') {
                                                c = str[18];
                                                if (c == 'r') {
                                                  c = str[19];
                                                  if (c == 't') {
                                                    c = str[20];
                                                    if (!c) return NEW_SRV_ACTION_ENABLE_VIRTUAL_START;
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
              } else {
              }
              return 0;
            }
          } else {
          }
          return 0;
        } else if (c < 'e') {
          if (c == 'd') {
            c = str[1];
            if (c == 'o') {
              c = str[2];
              if (c == 'w') {
                c = str[3];
                if (c == 'n') {
                  c = str[4];
                  if (c == 'l') {
                    c = str[5];
                    if (c == 'o') {
                      c = str[6];
                      if (c == 'a') {
                        c = str[7];
                        if (c == 'd') {
                          c = str[8];
                          if (c == '-') {
                            c = str[9];
                            if (c == 'r') {
                              c = str[10];
                              if (c == 'u') {
                                c = str[11];
                                if (c == 'n') {
                                  c = str[12];
                                  if (!c) return NEW_SRV_ACTION_DOWNLOAD_RUN;
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            } else if (c < 'r') {
                              if (c == 'a') {
                                c = str[10];
                                if (c == 'r') {
                                  c = str[11];
                                  if (c == 'c') {
                                    c = str[12];
                                    if (c == 'h') {
                                      c = str[13];
                                      if (c == 'i') {
                                        c = str[14];
                                        if (c == 'v') {
                                          c = str[15];
                                          if (c == 'e') {
                                            c = str[16];
                                            if (c == '-') {
                                              c = str[17];
                                              if (c == '2') {
                                                c = str[18];
                                                if (!c) return NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_2;
                                                return 0;
                                              } else if (c < '2') {
                                                if (c == '1') {
                                                  c = str[18];
                                                  if (!c) return NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_1;
                                                  return 0;
                                                }
                                              } else {
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                            } else {
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            } else if (c < 'o') {
              if (c == 'i') {
                c = str[2];
                if (c == 's') {
                  c = str[3];
                  if (c == 'q') {
                    c = str[4];
                    if (c == 'u') {
                      c = str[5];
                      if (c == 'a') {
                        c = str[6];
                        if (c == 'l') {
                          c = str[7];
                          if (c == 'i') {
                            c = str[8];
                            if (c == 'f') {
                              c = str[9];
                              if (c == 'y') {
                                c = str[10];
                                if (c == '-') {
                                  c = str[11];
                                  if (c == 'd') {
                                    c = str[12];
                                    if (c == 'i') {
                                      c = str[13];
                                      if (c == 's') {
                                        c = str[14];
                                        if (c == 'p') {
                                          c = str[15];
                                          if (c == 'l') {
                                            c = str[16];
                                            if (c == 'a') {
                                              c = str[17];
                                              if (c == 'y') {
                                                c = str[18];
                                                if (c == 'e') {
                                                  c = str[19];
                                                  if (c == 'd') {
                                                    c = str[20];
                                                    if (c == '-') {
                                                      c = str[21];
                                                      if (c == '2') {
                                                        c = str[22];
                                                        if (!c) return NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_2;
                                                        return 0;
                                                      } else if (c < '2') {
                                                        if (c == '1') {
                                                          c = str[22];
                                                          if (!c) return NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_1;
                                                          return 0;
                                                        }
                                                      } else {
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  } else if (c < 'q') {
                    if (c == 'a') {
                      c = str[4];
                      if (c == 'b') {
                        c = str[5];
                        if (c == 'l') {
                          c = str[6];
                          if (c == 'e') {
                            c = str[7];
                            if (c == '-') {
                              c = str[8];
                              if (c == 'v') {
                                c = str[9];
                                if (c == 'i') {
                                  c = str[10];
                                  if (c == 'r') {
                                    c = str[11];
                                    if (c == 't') {
                                      c = str[12];
                                      if (c == 'u') {
                                        c = str[13];
                                        if (c == 'a') {
                                          c = str[14];
                                          if (c == 'l') {
                                            c = str[15];
                                            if (c == '-') {
                                              c = str[16];
                                              if (c == 's') {
                                                c = str[17];
                                                if (c == 't') {
                                                  c = str[18];
                                                  if (c == 'a') {
                                                    c = str[19];
                                                    if (c == 'r') {
                                                      c = str[20];
                                                      if (c == 't') {
                                                        c = str[21];
                                                        if (!c) return NEW_SRV_ACTION_DISABLE_VIRTUAL_START;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                  } else {
                  }
                  return 0;
                }
                return 0;
              } else if (c < 'i') {
                if (c == 'e') {
                  c = str[2];
                  if (c == 'l') {
                    c = str[3];
                    if (c == 'e') {
                      c = str[4];
                      if (c == 't') {
                        c = str[5];
                        if (c == 'e') {
                          c = str[6];
                          if (c == '-') {
                            c = str[7];
                            if (c == 'a') {
                              c = str[8];
                              if (c == 'v') {
                                c = str[9];
                                if (c == 'a') {
                                  c = str[10];
                                  if (c == 't') {
                                    c = str[11];
                                    if (c == 'a') {
                                      c = str[12];
                                      if (c == 'r') {
                                        c = str[13];
                                        if (!c) return NEW_SRV_ACTION_DELETE_AVATAR;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              } else if (c < 'v') {
                                if (c == 'p') {
                                  c = str[9];
                                  if (c == 'i') {
                                    c = str[10];
                                    if (c == '-') {
                                      c = str[11];
                                      if (c == 'k') {
                                        c = str[12];
                                        if (c == 'e') {
                                          c = str[13];
                                          if (c == 'y') {
                                            c = str[14];
                                            if (!c) return NEW_SRV_ACTION_DELETE_API_KEY;
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                              } else {
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
              } else {
              }
            } else {
              if (c == 'u') {
                c = str[2];
                if (c == 'm') {
                  c = str[3];
                  if (c == 'p') {
                    c = str[4];
                    if (c == '-') {
                      c = str[5];
                      if (c == 'p') {
                        c = str[6];
                        if (c == 'r') {
                          c = str[7];
                          if (c == 'o') {
                            c = str[8];
                            if (c == 'b') {
                              c = str[9];
                              if (c == 'l') {
                                c = str[10];
                                if (c == 'e') {
                                  c = str[11];
                                  if (c == 'm') {
                                    c = str[12];
                                    if (c == 's') {
                                      c = str[13];
                                      if (!c) return NEW_SRV_ACTION_DUMP_PROBLEMS;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      } else if (c < 'p') {
                        if (c == 'l') {
                          c = str[6];
                          if (c == 'a') {
                            c = str[7];
                            if (c == 'n') {
                              c = str[8];
                              if (c == 'g') {
                                c = str[9];
                                if (c == 'u') {
                                  c = str[10];
                                  if (c == 'a') {
                                    c = str[11];
                                    if (c == 'g') {
                                      c = str[12];
                                      if (c == 'e') {
                                        c = str[13];
                                        if (c == 's') {
                                          c = str[14];
                                          if (!c) return NEW_SRV_ACTION_DUMP_LANGUAGES;
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 'l') {
                          if (c == 'c') {
                            c = str[6];
                            if (c == 'l') {
                              c = str[7];
                              if (c == 'a') {
                                c = str[8];
                                if (c == 'r') {
                                  c = str[9];
                                  if (!c) return NEW_SRV_ACTION_DUMP_CLAR;
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                        } else {
                          if (c == 'm') {
                            c = str[6];
                            if (c == 'a') {
                              c = str[7];
                              if (c == 's') {
                                c = str[8];
                                if (c == 't') {
                                  c = str[9];
                                  if (c == 'e') {
                                    c = str[10];
                                    if (c == 'r') {
                                      c = str[11];
                                      if (c == '-') {
                                        c = str[12];
                                        if (c == 'r') {
                                          c = str[13];
                                          if (c == 'u') {
                                            c = str[14];
                                            if (c == 'n') {
                                              c = str[15];
                                              if (c == 's') {
                                                c = str[16];
                                                if (!c) return NEW_SRV_ACTION_DUMP_MASTER_RUNS;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                        }
                      } else {
                        if (c == 's') {
                          c = str[6];
                          if (c == 'o') {
                            c = str[7];
                            if (c == 'u') {
                              c = str[8];
                              if (c == 'r') {
                                c = str[9];
                                if (c == 'c') {
                                  c = str[10];
                                  if (c == 'e') {
                                    c = str[11];
                                    if (!c) return NEW_SRV_ACTION_DUMP_SOURCE;
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 's') {
                          if (c == 'r') {
                            c = str[6];
                            if (c == 'u') {
                              c = str[7];
                              if (c == 'n') {
                                c = str[8];
                                if (c == '-') {
                                  c = str[9];
                                  if (c == 's') {
                                    c = str[10];
                                    if (c == 't') {
                                      c = str[11];
                                      if (c == 'a') {
                                        c = str[12];
                                        if (c == 't') {
                                          c = str[13];
                                          if (c == 'u') {
                                            c = str[14];
                                            if (c == 's') {
                                              c = str[15];
                                              if (!c) return NEW_SRV_ACTION_DUMP_RUN_STATUS;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            } else if (c < 'u') {
                              if (c == 'e') {
                                c = str[7];
                                if (c == 'p') {
                                  c = str[8];
                                  if (c == 'o') {
                                    c = str[9];
                                    if (c == 'r') {
                                      c = str[10];
                                      if (c == 't') {
                                        c = str[11];
                                        if (!c) return NEW_SRV_ACTION_DUMP_REPORT;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                            } else {
                            }
                            return 0;
                          }
                        } else {
                        }
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
            }
            return 0;
          }
        } else {
        }
      }
    } else {
      if (c == 'i') {
        c = str[1];
        if (c == 'n') {
          c = str[2];
          if (c == 'v') {
            c = str[3];
            if (c == 'o') {
              c = str[4];
              if (c == 'k') {
                c = str[5];
                if (c == 'e') {
                  c = str[6];
                  if (c == 'r') {
                    c = str[7];
                    if (c == '-') {
                      c = str[8];
                      if (c == 'r') {
                        c = str[9];
                        if (c == 'e') {
                          c = str[10];
                          if (c == 'b') {
                            c = str[11];
                            if (c == 'o') {
                              c = str[12];
                              if (c == 'o') {
                                c = str[13];
                                if (c == 't') {
                                  c = str[14];
                                  if (!c) return NEW_SRV_ACTION_INVOKER_REBOOT;
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      } else if (c < 'r') {
                        if (c == 'd') {
                          c = str[9];
                          if (c == 'o') {
                            c = str[10];
                            if (c == 'w') {
                              c = str[11];
                              if (c == 'n') {
                                c = str[12];
                                if (!c) return NEW_SRV_ACTION_INVOKER_DOWN;
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 'o') {
                            if (c == 'e') {
                              c = str[10];
                              if (c == 'l') {
                                c = str[11];
                                if (c == 'e') {
                                  c = str[12];
                                  if (c == 't') {
                                    c = str[13];
                                    if (c == 'e') {
                                      c = str[14];
                                      if (!c) return NEW_SRV_ACTION_INVOKER_DELETE;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          } else {
                          }
                          return 0;
                        }
                      } else {
                        if (c == 's') {
                          c = str[9];
                          if (c == 't') {
                            c = str[10];
                            if (c == 'o') {
                              c = str[11];
                              if (c == 'p') {
                                c = str[12];
                                if (!c) return NEW_SRV_ACTION_INVOKER_STOP;
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
          return 0;
        } else if (c < 'n') {
          if (c == 'g') {
            c = str[2];
            if (c == 'n') {
              c = str[3];
              if (c == 'o') {
                c = str[4];
                if (c == 'r') {
                  c = str[5];
                  if (c == 'e') {
                    c = str[6];
                    if (c == '-') {
                      c = str[7];
                      if (c == 'd') {
                        c = str[8];
                        if (c == 'i') {
                          c = str[9];
                          if (c == 's') {
                            c = str[10];
                            if (c == 'p') {
                              c = str[11];
                              if (c == 'l') {
                                c = str[12];
                                if (c == 'a') {
                                  c = str[13];
                                  if (c == 'y') {
                                    c = str[14];
                                    if (c == 'e') {
                                      c = str[15];
                                      if (c == 'd') {
                                        c = str[16];
                                        if (c == '-') {
                                          c = str[17];
                                          if (c == '2') {
                                            c = str[18];
                                            if (!c) return NEW_SRV_ACTION_IGNORE_DISPLAYED_2;
                                            return 0;
                                          } else if (c < '2') {
                                            if (c == '1') {
                                              c = str[18];
                                              if (!c) return NEW_SRV_ACTION_IGNORE_DISPLAYED_1;
                                              return 0;
                                            }
                                          } else {
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
        } else {
          if (c == 's') {
            c = str[2];
            if (c == 's') {
              c = str[3];
              if (c == 'u') {
                c = str[4];
                if (c == 'e') {
                  c = str[5];
                  if (c == '-') {
                    c = str[6];
                    if (c == 'w') {
                      c = str[7];
                      if (c == 'a') {
                        c = str[8];
                        if (c == 'r') {
                          c = str[9];
                          if (c == 'n') {
                            c = str[10];
                            if (c == 'i') {
                              c = str[11];
                              if (c == 'n') {
                                c = str[12];
                                if (c == 'g') {
                                  c = str[13];
                                  if (!c) return NEW_SRV_ACTION_ISSUE_WARNING;
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
        }
        return 0;
      } else if (c < 'i') {
        if (c == 'h') {
          c = str[1];
          if (c == 'a') {
            c = str[2];
            if (c == 's') {
              c = str[3];
              if (c == '-') {
                c = str[4];
                if (c == 't') {
                  c = str[5];
                  if (c == 'r') {
                    c = str[6];
                    if (c == 'a') {
                      c = str[7];
                      if (c == 'n') {
                        c = str[8];
                        if (c == 's') {
                          c = str[9];
                          if (c == 'i') {
                            c = str[10];
                            if (c == 'e') {
                              c = str[11];
                              if (c == 'n') {
                                c = str[12];
                                if (c == 't') {
                                  c = str[13];
                                  if (c == '-') {
                                    c = str[14];
                                    if (c == 'r') {
                                      c = str[15];
                                      if (c == 'u') {
                                        c = str[16];
                                        if (c == 'n') {
                                          c = str[17];
                                          if (c == 's') {
                                            c = str[18];
                                            if (!c) return NEW_SRV_ACTION_HAS_TRANSIENT_RUNS;
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
          return 0;
        } else if (c < 'h') {
          if (c == 'g') {
            c = str[1];
            if (c == 'e') {
              c = str[2];
              if (c == 't') {
                c = str[3];
                if (c == '-') {
                  c = str[4];
                  if (c == 'f') {
                    c = str[5];
                    if (c == 'i') {
                      c = str[6];
                      if (c == 'l') {
                        c = str[7];
                        if (c == 'e') {
                          c = str[8];
                          if (!c) return NEW_SRV_ACTION_GET_FILE;
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  } else if (c < 'f') {
                    if (c == 'c') {
                      c = str[5];
                      if (c == 'o') {
                        c = str[6];
                        if (c == 'n') {
                          c = str[7];
                          if (c == 't') {
                            c = str[8];
                            if (c == 'e') {
                              c = str[9];
                              if (c == 's') {
                                c = str[10];
                                if (c == 't') {
                                  c = str[11];
                                  if (c == '-') {
                                    c = str[12];
                                    if (c == 's') {
                                      c = str[13];
                                      if (c == 't') {
                                        c = str[14];
                                        if (c == 'a') {
                                          c = str[15];
                                          if (c == 't') {
                                            c = str[16];
                                            if (c == 'u') {
                                              c = str[17];
                                              if (c == 's') {
                                                c = str[18];
                                                if (!c) return NEW_SRV_ACTION_GET_CONTEST_STATUS;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      } else if (c < 't') {
                                        if (c == 'c') {
                                          c = str[14];
                                          if (c == 'h') {
                                            c = str[15];
                                            if (c == 'e') {
                                              c = str[16];
                                              if (c == 'd') {
                                                c = str[17];
                                                if (!c) return NEW_SRV_ACTION_GET_CONTEST_SCHED;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                      } else {
                                      }
                                      return 0;
                                    } else if (c < 's') {
                                      if (c == 'n') {
                                        c = str[13];
                                        if (c == 'a') {
                                          c = str[14];
                                          if (c == 'm') {
                                            c = str[15];
                                            if (c == 'e') {
                                              c = str[16];
                                              if (!c) return NEW_SRV_ACTION_GET_CONTEST_NAME;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      } else if (c < 'n') {
                                        if (c == 'd') {
                                          c = str[13];
                                          if (c == 'u') {
                                            c = str[14];
                                            if (c == 'r') {
                                              c = str[15];
                                              if (c == 'a') {
                                                c = str[16];
                                                if (c == 't') {
                                                  c = str[17];
                                                  if (c == 'i') {
                                                    c = str[18];
                                                    if (c == 'o') {
                                                      c = str[19];
                                                      if (c == 'n') {
                                                        c = str[20];
                                                        if (!c) return NEW_SRV_ACTION_GET_CONTEST_DURATION;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          } else if (c < 'u') {
                                            if (c == 'e') {
                                              c = str[14];
                                              if (c == 's') {
                                                c = str[15];
                                                if (c == 'c') {
                                                  c = str[16];
                                                  if (c == 'r') {
                                                    c = str[17];
                                                    if (c == 'i') {
                                                      c = str[18];
                                                      if (c == 'p') {
                                                        c = str[19];
                                                        if (c == 't') {
                                                          c = str[20];
                                                          if (c == 'i') {
                                                            c = str[21];
                                                            if (c == 'o') {
                                                              c = str[22];
                                                              if (c == 'n') {
                                                                c = str[23];
                                                                if (!c) return NEW_SRV_ACTION_GET_CONTEST_DESCRIPTION;
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                          } else {
                                          }
                                          return 0;
                                        }
                                      } else {
                                      }
                                    } else {
                                      if (c == 't') {
                                        c = str[13];
                                        if (c == 'y') {
                                          c = str[14];
                                          if (c == 'p') {
                                            c = str[15];
                                            if (c == 'e') {
                                              c = str[16];
                                              if (!c) return NEW_SRV_ACTION_GET_CONTEST_TYPE;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    } else if (c < 'c') {
                      if (c == 'a') {
                        c = str[5];
                        if (c == 'v') {
                          c = str[6];
                          if (c == 'a') {
                            c = str[7];
                            if (c == 't') {
                              c = str[8];
                              if (c == 'a') {
                                c = str[9];
                                if (c == 'r') {
                                  c = str[10];
                                  if (!c) return NEW_SRV_ACTION_GET_AVATAR;
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                    } else {
                    }
                  } else {
                    if (c == 'u') {
                      c = str[5];
                      if (c == 's') {
                        c = str[6];
                        if (c == 'e') {
                          c = str[7];
                          if (c == 'r') {
                            c = str[8];
                            if (c == 'p') {
                              c = str[9];
                              if (c == 'r') {
                                c = str[10];
                                if (c == 'o') {
                                  c = str[11];
                                  if (c == 'b') {
                                    c = str[12];
                                    if (!c) return NEW_SRV_ACTION_GET_USERPROB;
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    } else if (c < 'u') {
                      if (c == 's') {
                        c = str[5];
                        if (c == 'u') {
                          c = str[6];
                          if (c == 'b') {
                            c = str[7];
                            if (c == 'm') {
                              c = str[8];
                              if (c == 'i') {
                                c = str[9];
                                if (c == 't') {
                                  c = str[10];
                                  if (!c) return NEW_SRV_ACTION_GET_SUBMIT;
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                    } else {
                    }
                  }
                  return 0;
                }
                return 0;
              } else if (c < 't') {
                if (c == 'n') {
                  c = str[3];
                  if (c == 'e') {
                    c = str[4];
                    if (c == 'r') {
                      c = str[5];
                      if (c == 'a') {
                        c = str[6];
                        if (c == 't') {
                          c = str[7];
                          if (c == 'e') {
                            c = str[8];
                            if (c == '-') {
                              c = str[9];
                              if (c == 'r') {
                                c = str[10];
                                if (c == 'e') {
                                  c = str[11];
                                  if (c == 'g') {
                                    c = str[12];
                                    if (c == '-') {
                                      c = str[13];
                                      if (c == 'p') {
                                        c = str[14];
                                        if (c == 'a') {
                                          c = str[15];
                                          if (c == 's') {
                                            c = str[16];
                                            if (c == 's') {
                                              c = str[17];
                                              if (c == 'w') {
                                                c = str[18];
                                                if (c == 'o') {
                                                  c = str[19];
                                                  if (c == 'r') {
                                                    c = str[20];
                                                    if (c == 'd') {
                                                      c = str[21];
                                                      if (c == 's') {
                                                        c = str[22];
                                                        if (c == '-') {
                                                          c = str[23];
                                                          if (c == '2') {
                                                            c = str[24];
                                                            if (!c) return NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_2;
                                                            return 0;
                                                          } else if (c < '2') {
                                                            if (c == '1') {
                                                              c = str[24];
                                                              if (!c) return NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_1;
                                                              return 0;
                                                            }
                                                          } else {
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              } else if (c < 'r') {
                                if (c == 'p') {
                                  c = str[10];
                                  if (c == 'a') {
                                    c = str[11];
                                    if (c == 's') {
                                      c = str[12];
                                      if (c == 's') {
                                        c = str[13];
                                        if (c == 'w') {
                                          c = str[14];
                                          if (c == 'o') {
                                            c = str[15];
                                            if (c == 'r') {
                                              c = str[16];
                                              if (c == 'd') {
                                                c = str[17];
                                                if (c == 's') {
                                                  c = str[18];
                                                  if (c == '-') {
                                                    c = str[19];
                                                    if (c == '2') {
                                                      c = str[20];
                                                      if (!c) return NEW_SRV_ACTION_GENERATE_PASSWORDS_2;
                                                      return 0;
                                                    } else if (c < '2') {
                                                      if (c == '1') {
                                                        c = str[20];
                                                        if (!c) return NEW_SRV_ACTION_GENERATE_PASSWORDS_1;
                                                        return 0;
                                                      }
                                                    } else {
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                              } else {
                                if (c == 't') {
                                  c = str[10];
                                  if (c == 'e') {
                                    c = str[11];
                                    if (c == 'l') {
                                      c = str[12];
                                      if (c == 'e') {
                                        c = str[13];
                                        if (c == 'g') {
                                          c = str[14];
                                          if (c == 'r') {
                                            c = str[15];
                                            if (c == 'a') {
                                              c = str[16];
                                              if (c == 'm') {
                                                c = str[17];
                                                if (c == '-') {
                                                  c = str[18];
                                                  if (c == 't') {
                                                    c = str[19];
                                                    if (c == 'o') {
                                                      c = str[20];
                                                      if (c == 'k') {
                                                        c = str[21];
                                                        if (c == 'e') {
                                                          c = str[22];
                                                          if (c == 'n') {
                                                            c = str[23];
                                                            if (!c) return NEW_SRV_ACTION_GENERATE_TELEGRAM_TOKEN;
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
              } else {
              }
              return 0;
            }
            return 0;
          }
        } else {
        }
      } else {
        if (c == 'j') {
          c = str[1];
          if (c == 's') {
            c = str[2];
            if (c == 'o') {
              c = str[3];
              if (c == 'n') {
                c = str[4];
                if (c == '-') {
                  c = str[5];
                  if (c == 'u') {
                    c = str[6];
                    if (c == 's') {
                      c = str[7];
                      if (c == 'e') {
                        c = str[8];
                        if (c == 'r') {
                          c = str[9];
                          if (c == '-') {
                            c = str[10];
                            if (c == 's') {
                              c = str[11];
                              if (c == 't') {
                                c = str[12];
                                if (c == 'a') {
                                  c = str[13];
                                  if (c == 't') {
                                    c = str[14];
                                    if (c == 'e') {
                                      c = str[15];
                                      if (!c) return NEW_SRV_ACTION_JSON_USER_STATE;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
          return 0;
        }
      }
    }
  } else {
    if (c == 's') {
      c = str[1];
      if (c == 'o') {
        c = str[2];
        if (c == 'f') {
          c = str[3];
          if (c == 't') {
            c = str[4];
            if (c == '-') {
              c = str[5];
              if (c == 'u') {
                c = str[6];
                if (c == 'p') {
                  c = str[7];
                  if (c == 'd') {
                    c = str[8];
                    if (c == 'a') {
                      c = str[9];
                      if (c == 't') {
                        c = str[10];
                        if (c == 'e') {
                          c = str[11];
                          if (c == '-') {
                            c = str[12];
                            if (c == 's') {
                              c = str[13];
                              if (c == 't') {
                                c = str[14];
                                if (c == 'a') {
                                  c = str[15];
                                  if (c == 'n') {
                                    c = str[16];
                                    if (c == 'd') {
                                      c = str[17];
                                      if (c == 'i') {
                                        c = str[18];
                                        if (c == 'n') {
                                          c = str[19];
                                          if (c == 'g') {
                                            c = str[20];
                                            if (c == 's') {
                                              c = str[21];
                                              if (!c) return NEW_SRV_ACTION_SOFT_UPDATE_STANDINGS;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
          return 0;
        }
        return 0;
      } else if (c < 'o') {
        if (c == 'c') {
          c = str[2];
          if (c == 'h') {
            c = str[3];
            if (c == 'e') {
              c = str[4];
              if (c == 'd') {
                c = str[5];
                if (c == 'u') {
                  c = str[6];
                  if (c == 'l') {
                    c = str[7];
                    if (c == 'e') {
                      c = str[8];
                      if (!c) return NEW_SRV_ACTION_SCHEDULE;
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
          return 0;
        } else if (c < 'c') {
          if (c == 'a') {
            c = str[2];
            if (c == 'v') {
              c = str[3];
              if (c == 'e') {
                c = str[4];
                if (c == '-') {
                  c = str[5];
                  if (c == 'u') {
                    c = str[6];
                    if (c == 's') {
                      c = str[7];
                      if (c == 'e') {
                        c = str[8];
                        if (c == 'r') {
                          c = str[9];
                          if (c == 'p') {
                            c = str[10];
                            if (c == 'r') {
                              c = str[11];
                              if (c == 'o') {
                                c = str[12];
                                if (c == 'b') {
                                  c = str[13];
                                  if (!c) return NEW_SRV_ACTION_SAVE_USERPROB;
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  } else if (c < 'u') {
                    if (c == 'c') {
                      c = str[6];
                      if (c == 'r') {
                        c = str[7];
                        if (c == 'o') {
                          c = str[8];
                          if (c == 'p') {
                            c = str[9];
                            if (c == 'p') {
                              c = str[10];
                              if (c == 'e') {
                                c = str[11];
                                if (c == 'd') {
                                  c = str[12];
                                  if (c == '-') {
                                    c = str[13];
                                    if (c == 'a') {
                                      c = str[14];
                                      if (c == 'v') {
                                        c = str[15];
                                        if (c == 'a') {
                                          c = str[16];
                                          if (c == 't') {
                                            c = str[17];
                                            if (c == 'a') {
                                              c = str[18];
                                              if (c == 'r') {
                                                c = str[19];
                                                if (c == '-') {
                                                  c = str[20];
                                                  if (c == 'a') {
                                                    c = str[21];
                                                    if (c == 'j') {
                                                      c = str[22];
                                                      if (c == 'a') {
                                                        c = str[23];
                                                        if (c == 'x') {
                                                          c = str[24];
                                                          if (!c) return NEW_SRV_ACTION_SAVE_CROPPED_AVATAR_AJAX;
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                  } else {
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
        } else {
          if (c == 'e') {
            c = str[2];
            if (c == 's') {
              c = str[3];
              if (c == 's') {
                c = str[4];
                if (c == 'i') {
                  c = str[5];
                  if (c == 'o') {
                    c = str[6];
                    if (c == 'n') {
                      c = str[7];
                      if (c == '-') {
                        c = str[8];
                        if (c == 'i') {
                          c = str[9];
                          if (c == 'n') {
                            c = str[10];
                            if (c == 'f') {
                              c = str[11];
                              if (c == 'o') {
                                c = str[12];
                                if (c == '-') {
                                  c = str[13];
                                  if (c == 'j') {
                                    c = str[14];
                                    if (c == 's') {
                                      c = str[15];
                                      if (c == 'o') {
                                        c = str[16];
                                        if (c == 'n') {
                                          c = str[17];
                                          if (!c) return NEW_SRV_ACTION_SESSION_INFO_JSON;
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            } else if (c < 's') {
              if (c == 'r') {
                c = str[3];
                if (c == 'v') {
                  c = str[4];
                  if (c == 'e') {
                    c = str[5];
                    if (c == 'r') {
                      c = str[6];
                      if (c == '-') {
                        c = str[7];
                        if (c == 'i') {
                          c = str[8];
                          if (c == 'n') {
                            c = str[9];
                            if (c == 'f') {
                              c = str[10];
                              if (c == 'o') {
                                c = str[11];
                                if (c == '-') {
                                  c = str[12];
                                  if (c == 'p') {
                                    c = str[13];
                                    if (c == 'a') {
                                      c = str[14];
                                      if (c == 'g') {
                                        c = str[15];
                                        if (c == 'e') {
                                          c = str[16];
                                          if (!c) return NEW_SRV_ACTION_SERVER_INFO_PAGE;
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
            } else {
              if (c == 't') {
                c = str[3];
                if (c == '-') {
                  c = str[4];
                  if (c == 'p') {
                    c = str[5];
                    if (c == 'r') {
                      c = str[6];
                      if (c == 'i') {
                        c = str[7];
                        if (c == 'o') {
                          c = str[8];
                          if (c == 'r') {
                            c = str[9];
                            if (c == 'i') {
                              c = str[10];
                              if (c == 't') {
                                c = str[11];
                                if (c == 'i') {
                                  c = str[12];
                                  if (c == 'e') {
                                    c = str[13];
                                    if (c == 's') {
                                      c = str[14];
                                      if (!c) return NEW_SRV_ACTION_SET_PRIORITIES;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  } else if (c < 'p') {
                    if (c == 'd') {
                      c = str[5];
                      if (c == 'i') {
                        c = str[6];
                        if (c == 's') {
                          c = str[7];
                          if (c == 'q') {
                            c = str[8];
                            if (c == 'u') {
                              c = str[9];
                              if (c == 'a') {
                                c = str[10];
                                if (c == 'l') {
                                  c = str[11];
                                  if (c == 'i') {
                                    c = str[12];
                                    if (c == 'f') {
                                      c = str[13];
                                      if (c == 'i') {
                                        c = str[14];
                                        if (c == 'c') {
                                          c = str[15];
                                          if (c == 'a') {
                                            c = str[16];
                                            if (c == 't') {
                                              c = str[17];
                                              if (c == 'i') {
                                                c = str[18];
                                                if (c == 'o') {
                                                  c = str[19];
                                                  if (c == 'n') {
                                                    c = str[20];
                                                    if (!c) return NEW_SRV_ACTION_SET_DISQUALIFICATION;
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    } else if (c < 'd') {
                      if (c == 'a') {
                        c = str[5];
                        if (c == 'c') {
                          c = str[6];
                          if (c == 'c') {
                            c = str[7];
                            if (c == 'e') {
                              c = str[8];
                              if (c == 'p') {
                                c = str[9];
                                if (c == 't') {
                                  c = str[10];
                                  if (c == 'i') {
                                    c = str[11];
                                    if (c == 'n') {
                                      c = str[12];
                                      if (c == 'g') {
                                        c = str[13];
                                        if (c == '-') {
                                          c = str[14];
                                          if (c == 'm') {
                                            c = str[15];
                                            if (c == 'o') {
                                              c = str[16];
                                              if (c == 'd') {
                                                c = str[17];
                                                if (c == 'e') {
                                                  c = str[18];
                                                  if (!c) return NEW_SRV_ACTION_SET_ACCEPTING_MODE;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                    } else {
                      if (c == 'j') {
                        c = str[5];
                        if (c == 'u') {
                          c = str[6];
                          if (c == 'd') {
                            c = str[7];
                            if (c == 'g') {
                              c = str[8];
                              if (c == 'i') {
                                c = str[9];
                                if (c == 'n') {
                                  c = str[10];
                                  if (c == 'g') {
                                    c = str[11];
                                    if (c == '-') {
                                      c = str[12];
                                      if (c == 'm') {
                                        c = str[13];
                                        if (c == 'o') {
                                          c = str[14];
                                          if (c == 'd') {
                                            c = str[15];
                                            if (c == 'e') {
                                              c = str[16];
                                              if (!c) return NEW_SRV_ACTION_SET_JUDGING_MODE;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                    }
                  } else {
                    if (c == 't') {
                      c = str[5];
                      if (c == 'e') {
                        c = str[6];
                        if (c == 's') {
                          c = str[7];
                          if (c == 't') {
                            c = str[8];
                            if (c == 'i') {
                              c = str[9];
                              if (c == 'n') {
                                c = str[10];
                                if (c == 'g') {
                                  c = str[11];
                                  if (c == '-') {
                                    c = str[12];
                                    if (c == 'f') {
                                      c = str[13];
                                      if (c == 'i') {
                                        c = str[14];
                                        if (c == 'n') {
                                          c = str[15];
                                          if (c == 'i') {
                                            c = str[16];
                                            if (c == 's') {
                                              c = str[17];
                                              if (c == 'h') {
                                                c = str[18];
                                                if (c == 'e') {
                                                  c = str[19];
                                                  if (c == 'd') {
                                                    c = str[20];
                                                    if (c == '-') {
                                                      c = str[21];
                                                      if (c == 'f') {
                                                        c = str[22];
                                                        if (c == 'l') {
                                                          c = str[23];
                                                          if (c == 'a') {
                                                            c = str[24];
                                                            if (c == 'g') {
                                                              c = str[25];
                                                              if (!c) return NEW_SRV_ACTION_SET_TESTING_FINISHED_FLAG;
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    } else if (c < 't') {
                      if (c == 's') {
                        c = str[5];
                        if (c == 't') {
                          c = str[6];
                          if (c == 'a') {
                            c = str[7];
                            if (c == 'n') {
                              c = str[8];
                              if (c == 'd') {
                                c = str[9];
                                if (c == '-') {
                                  c = str[10];
                                  if (c == 'f') {
                                    c = str[11];
                                    if (c == 'i') {
                                      c = str[12];
                                      if (c == 'l') {
                                        c = str[13];
                                        if (c == 't') {
                                          c = str[14];
                                          if (c == 'e') {
                                            c = str[15];
                                            if (c == 'r') {
                                              c = str[16];
                                              if (!c) return NEW_SRV_ACTION_SET_STAND_FILTER;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                    } else {
                    }
                  }
                  return 0;
                }
                return 0;
              }
            }
            return 0;
          }
        }
      } else {
        if (c == 't') {
          c = str[2];
          if (c == 'o') {
            c = str[3];
            if (c == 'p') {
              c = str[4];
              if (c == '-') {
                c = str[5];
                if (c == 'c') {
                  c = str[6];
                  if (c == 'o') {
                    c = str[7];
                    if (c == 'n') {
                      c = str[8];
                      if (c == 't') {
                        c = str[9];
                        if (c == 'e') {
                          c = str[10];
                          if (c == 's') {
                            c = str[11];
                            if (c == 't') {
                              c = str[12];
                              if (!c) return NEW_SRV_ACTION_STOP_CONTEST;
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          } else if (c < 'o') {
            if (c == 'a') {
              c = str[3];
              if (c == 'r') {
                c = str[4];
                if (c == 't') {
                  c = str[5];
                  if (c == '-') {
                    c = str[6];
                    if (c == 'c') {
                      c = str[7];
                      if (c == 'o') {
                        c = str[8];
                        if (c == 'n') {
                          c = str[9];
                          if (c == 't') {
                            c = str[10];
                            if (c == 'e') {
                              c = str[11];
                              if (c == 's') {
                                c = str[12];
                                if (c == 't') {
                                  c = str[13];
                                  if (!c) return NEW_SRV_ACTION_START_CONTEST;
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              } else if (c < 'r') {
                if (c == 'n') {
                  c = str[4];
                  if (c == 'd') {
                    c = str[5];
                    if (c == 'i') {
                      c = str[6];
                      if (c == 'n') {
                        c = str[7];
                        if (c == 'g') {
                          c = str[8];
                          if (c == 's') {
                            c = str[9];
                            if (!c) return NEW_SRV_ACTION_STANDINGS;
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
              } else {
              }
              return 0;
            }
          } else {
          }
          return 0;
        } else if (c < 't') {
          if (c == 'q') {
            c = str[2];
            if (c == 'u') {
              c = str[3];
              if (c == 'e') {
                c = str[4];
                if (c == 'e') {
                  c = str[5];
                  if (c == 'z') {
                    c = str[6];
                    if (c == 'e') {
                      c = str[7];
                      if (c == '-') {
                        c = str[8];
                        if (c == 'r') {
                          c = str[9];
                          if (c == 'u') {
                            c = str[10];
                            if (c == 'n') {
                              c = str[11];
                              if (c == 's') {
                                c = str[12];
                                if (!c) return NEW_SRV_ACTION_SQUEEZE_RUNS;
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
        } else {
          if (c == 'u') {
            c = str[2];
            if (c == 's') {
              c = str[3];
              if (c == 'p') {
                c = str[4];
                if (c == 'e') {
                  c = str[5];
                  if (c == 'n') {
                    c = str[6];
                    if (c == 'd') {
                      c = str[7];
                      if (!c) return NEW_SRV_ACTION_SUSPEND;
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            } else if (c < 's') {
              if (c == 'b') {
                c = str[3];
                if (c == 'm') {
                  c = str[4];
                  if (c == 'i') {
                    c = str[5];
                    if (c == 't') {
                      c = str[6];
                      if (c == '-') {
                        c = str[7];
                        if (c == 'c') {
                          c = str[8];
                          if (c == 'l') {
                            c = str[9];
                            if (c == 'a') {
                              c = str[10];
                              if (c == 'r') {
                                c = str[11];
                                if (!c) return NEW_SRV_ACTION_SUBMIT_CLAR;
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 'c') {
                          if (c == 'a') {
                            c = str[8];
                            if (c == 'p') {
                              c = str[9];
                              if (c == 'p') {
                                c = str[10];
                                if (c == 'e') {
                                  c = str[11];
                                  if (c == 'a') {
                                    c = str[12];
                                    if (c == 'l') {
                                      c = str[13];
                                      if (!c) return NEW_SRV_ACTION_SUBMIT_APPEAL;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                        } else {
                          if (c == 'r') {
                            c = str[8];
                            if (c == 'u') {
                              c = str[9];
                              if (c == 'n') {
                                c = str[10];
                                if (!c) return NEW_SRV_ACTION_SUBMIT_RUN;
                                if (c == '-') {
                                  c = str[11];
                                  if (c == 'i') {
                                    c = str[12];
                                    if (c == 'n') {
                                      c = str[13];
                                      if (c == 'p') {
                                        c = str[14];
                                        if (c == 'u') {
                                          c = str[15];
                                          if (c == 't') {
                                            c = str[16];
                                            if (!c) return NEW_SRV_ACTION_SUBMIT_RUN_INPUT;
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  } else if (c < 'i') {
                                    if (c == 'b') {
                                      c = str[12];
                                      if (c == 'a') {
                                        c = str[13];
                                        if (c == 't') {
                                          c = str[14];
                                          if (c == 'c') {
                                            c = str[15];
                                            if (c == 'h') {
                                              c = str[16];
                                              if (!c) return NEW_SRV_ACTION_SUBMIT_RUN_BATCH;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                  } else {
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
            } else {
            }
            return 0;
          }
        }
      }
      return 0;
    } else if (c < 's') {
      if (c == 'o') {
        c = str[1];
        if (c == 'a') {
          c = str[2];
          if (c == 'u') {
            c = str[3];
            if (c == 't') {
              c = str[4];
              if (c == 'h') {
                c = str[5];
                if (c == '-') {
                  c = str[6];
                  if (c == 'l') {
                    c = str[7];
                    if (c == 'o') {
                      c = str[8];
                      if (c == 'g') {
                        c = str[9];
                        if (c == 'i') {
                          c = str[10];
                          if (c == 'n') {
                            c = str[11];
                            if (c == '-') {
                              c = str[12];
                              if (c == '2') {
                                c = str[13];
                                if (!c) return NEW_SRV_ACTION_OAUTH_LOGIN_2;
                                return 0;
                              } else if (c < '2') {
                                if (c == '1') {
                                  c = str[13];
                                  if (!c) return NEW_SRV_ACTION_OAUTH_LOGIN_1;
                                  return 0;
                                }
                              } else {
                                if (c == '3') {
                                  c = str[13];
                                  if (!c) return NEW_SRV_ACTION_OAUTH_LOGIN_3;
                                  return 0;
                                }
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
          return 0;
        }
        return 0;
      } else if (c < 'o') {
        if (c == 'n') {
          c = str[1];
          if (c == 'e') {
            c = str[2];
            if (c == 'w') {
              c = str[3];
              if (c == '-') {
                c = str[4];
                if (c == 'r') {
                  c = str[5];
                  if (c == 'u') {
                    c = str[6];
                    if (c == 'n') {
                      c = str[7];
                      if (!c) return NEW_SRV_ACTION_NEW_RUN;
                      if (c == '-') {
                        c = str[8];
                        if (c == 'f') {
                          c = str[9];
                          if (c == 'o') {
                            c = str[10];
                            if (c == 'r') {
                              c = str[11];
                              if (c == 'm') {
                                c = str[12];
                                if (!c) return NEW_SRV_ACTION_NEW_RUN_FORM;
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
          return 0;
        } else if (c < 'n') {
          if (c == 'm') {
            c = str[1];
            if (c == 'a') {
              c = str[2];
              if (c == 'r') {
                c = str[3];
                if (c == 'k') {
                  c = str[4];
                  if (c == '-') {
                    c = str[5];
                    if (c == 'd') {
                      c = str[6];
                      if (c == 'i') {
                        c = str[7];
                        if (c == 's') {
                          c = str[8];
                          if (c == 'p') {
                            c = str[9];
                            if (c == 'l') {
                              c = str[10];
                              if (c == 'a') {
                                c = str[11];
                                if (c == 'y') {
                                  c = str[12];
                                  if (c == 'e') {
                                    c = str[13];
                                    if (c == 'd') {
                                      c = str[14];
                                      if (c == '-') {
                                        c = str[15];
                                        if (c == '2') {
                                          c = str[16];
                                          if (!c) return NEW_SRV_ACTION_MARK_DISPLAYED_2;
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              } else if (c < 'r') {
                if (c == 'i') {
                  c = str[3];
                  if (c == 'n') {
                    c = str[4];
                    if (c == '-') {
                      c = str[5];
                      if (c == 'p') {
                        c = str[6];
                        if (c == 'a') {
                          c = str[7];
                          if (c == 'g') {
                            c = str[8];
                            if (c == 'e') {
                              c = str[9];
                              if (!c) return NEW_SRV_ACTION_MAIN_PAGE;
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
              } else {
              }
              return 0;
            }
            return 0;
          }
        } else {
        }
      } else {
        if (c == 'r') {
          c = str[1];
          if (c == 'e') {
            c = str[2];
            if (c == 'l') {
              c = str[3];
              if (c == 'o') {
                c = str[4];
                if (c == 'a') {
                  c = str[5];
                  if (c == 'd') {
                    c = str[6];
                    if (c == '-') {
                      c = str[7];
                      if (c == 'c') {
                        c = str[8];
                        if (c == 'o') {
                          c = str[9];
                          if (c == 'n') {
                            c = str[10];
                            if (c == 't') {
                              c = str[11];
                              if (c == 'e') {
                                c = str[12];
                                if (c == 's') {
                                  c = str[13];
                                  if (c == 't') {
                                    c = str[14];
                                    if (c == '-') {
                                      c = str[15];
                                      if (c == 'p') {
                                        c = str[16];
                                        if (c == 'a') {
                                          c = str[17];
                                          if (c == 'g') {
                                            c = str[18];
                                            if (c == 'e') {
                                              c = str[19];
                                              if (c == 's') {
                                                c = str[20];
                                                if (!c) return NEW_SRV_ACTION_RELOAD_CONTEST_PAGES;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      } else if (c < 'c') {
                        if (c == 'a') {
                          c = str[8];
                          if (c == 'l') {
                            c = str[9];
                            if (c == 'l') {
                              c = str[10];
                              if (c == '-') {
                                c = str[11];
                                if (c == 'c') {
                                  c = str[12];
                                  if (c == 'o') {
                                    c = str[13];
                                    if (c == 'n') {
                                      c = str[14];
                                      if (c == 't') {
                                        c = str[15];
                                        if (c == 'e') {
                                          c = str[16];
                                          if (c == 's') {
                                            c = str[17];
                                            if (c == 't') {
                                              c = str[18];
                                              if (c == '-') {
                                                c = str[19];
                                                if (c == 'p') {
                                                  c = str[20];
                                                  if (c == 'a') {
                                                    c = str[21];
                                                    if (c == 'g') {
                                                      c = str[22];
                                                      if (c == 'e') {
                                                        c = str[23];
                                                        if (c == 's') {
                                                          c = str[24];
                                                          if (!c) return NEW_SRV_ACTION_RELOAD_ALL_CONTEST_PAGES;
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                      } else {
                        if (c == 's') {
                          c = str[8];
                          if (c == 't') {
                            c = str[9];
                            if (c == 'a') {
                              c = str[10];
                              if (c == 't') {
                                c = str[11];
                                if (c == 'e') {
                                  c = str[12];
                                  if (c == 'm') {
                                    c = str[13];
                                    if (c == 'e') {
                                      c = str[14];
                                      if (c == 'n') {
                                        c = str[15];
                                        if (c == 't') {
                                          c = str[16];
                                          if (!c) return NEW_SRV_ACTION_RELOAD_STATEMENT;
                                          if (c == '-') {
                                            c = str[17];
                                            if (c == 'a') {
                                              c = str[18];
                                              if (c == 'l') {
                                                c = str[19];
                                                if (c == 'l') {
                                                  c = str[20];
                                                  if (!c) return NEW_SRV_ACTION_RELOAD_STATEMENT_ALL;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 't') {
                            if (c == 'e') {
                              c = str[9];
                              if (c == 'r') {
                                c = str[10];
                                if (c == 'v') {
                                  c = str[11];
                                  if (c == 'e') {
                                    c = str[12];
                                    if (c == 'r') {
                                      c = str[13];
                                      if (!c) return NEW_SRV_ACTION_RELOAD_SERVER;
                                      if (c == '-') {
                                        c = str[14];
                                        if (c == 'a') {
                                          c = str[15];
                                          if (c == 'l') {
                                            c = str[16];
                                            if (c == 'l') {
                                              c = str[17];
                                              if (!c) return NEW_SRV_ACTION_RELOAD_SERVER_ALL;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        } else if (c < 'a') {
                                          if (c == '2') {
                                            c = str[15];
                                            if (!c) return NEW_SRV_ACTION_RELOAD_SERVER_2;
                                            return 0;
                                          }
                                        } else {
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          } else {
                          }
                          return 0;
                        }
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            } else if (c < 'l') {
              if (c == 'j') {
                c = str[3];
                if (c == 'u') {
                  c = str[4];
                  if (c == 'd') {
                    c = str[5];
                    if (c == 'g') {
                      c = str[6];
                      if (c == 'e') {
                        c = str[7];
                        if (c == '-') {
                          c = str[8];
                          if (c == 'p') {
                            c = str[9];
                            if (c == 'r') {
                              c = str[10];
                              if (c == 'o') {
                                c = str[11];
                                if (c == 'b') {
                                  c = str[12];
                                  if (c == 'l') {
                                    c = str[13];
                                    if (c == 'e') {
                                      c = str[14];
                                      if (c == 'm') {
                                        c = str[15];
                                        if (c == '-') {
                                          c = str[16];
                                          if (c == '2') {
                                            c = str[17];
                                            if (!c) return NEW_SRV_ACTION_REJUDGE_PROBLEM_2;
                                            return 0;
                                          } else if (c < '2') {
                                            if (c == '1') {
                                              c = str[17];
                                              if (!c) return NEW_SRV_ACTION_REJUDGE_PROBLEM_1;
                                              return 0;
                                            }
                                          } else {
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 'p') {
                            if (c == 'd') {
                              c = str[9];
                              if (c == 'i') {
                                c = str[10];
                                if (c == 's') {
                                  c = str[11];
                                  if (c == 'p') {
                                    c = str[12];
                                    if (c == 'l') {
                                      c = str[13];
                                      if (c == 'a') {
                                        c = str[14];
                                        if (c == 'y') {
                                          c = str[15];
                                          if (c == 'e') {
                                            c = str[16];
                                            if (c == 'd') {
                                              c = str[17];
                                              if (c == '-') {
                                                c = str[18];
                                                if (c == '2') {
                                                  c = str[19];
                                                  if (!c) return NEW_SRV_ACTION_REJUDGE_DISPLAYED_2;
                                                  return 0;
                                                } else if (c < '2') {
                                                  if (c == '1') {
                                                    c = str[19];
                                                    if (!c) return NEW_SRV_ACTION_REJUDGE_DISPLAYED_1;
                                                    return 0;
                                                  }
                                                } else {
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            } else if (c < 'd') {
                              if (c == 'a') {
                                c = str[9];
                                if (c == 'l') {
                                  c = str[10];
                                  if (c == 'l') {
                                    c = str[11];
                                    if (c == '-') {
                                      c = str[12];
                                      if (c == '2') {
                                        c = str[13];
                                        if (!c) return NEW_SRV_ACTION_REJUDGE_ALL_2;
                                        return 0;
                                      } else if (c < '2') {
                                        if (c == '1') {
                                          c = str[13];
                                          if (!c) return NEW_SRV_ACTION_REJUDGE_ALL_1;
                                          return 0;
                                        }
                                      } else {
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                            } else {
                            }
                          } else {
                            if (c == 's') {
                              c = str[9];
                              if (c == 'u') {
                                c = str[10];
                                if (c == 's') {
                                  c = str[11];
                                  if (c == 'p') {
                                    c = str[12];
                                    if (c == 'e') {
                                      c = str[13];
                                      if (c == 'n') {
                                        c = str[14];
                                        if (c == 'd') {
                                          c = str[15];
                                          if (c == 'e') {
                                            c = str[16];
                                            if (c == 'd') {
                                              c = str[17];
                                              if (c == '-') {
                                                c = str[18];
                                                if (c == '2') {
                                                  c = str[19];
                                                  if (!c) return NEW_SRV_ACTION_REJUDGE_SUSPENDED_2;
                                                  return 0;
                                                } else if (c < '2') {
                                                  if (c == '1') {
                                                    c = str[19];
                                                    if (!c) return NEW_SRV_ACTION_REJUDGE_SUSPENDED_1;
                                                    return 0;
                                                  }
                                                } else {
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              } else if (c < 'j') {
                if (c == 'g') {
                  c = str[3];
                  if (c == '-') {
                    c = str[4];
                    if (c == 'l') {
                      c = str[5];
                      if (c == 'o') {
                        c = str[6];
                        if (c == 'g') {
                          c = str[7];
                          if (c == 'i') {
                            c = str[8];
                            if (c == 'n') {
                              c = str[9];
                              if (!c) return NEW_SRV_ACTION_REG_LOGIN;
                              if (c == '-') {
                                c = str[10];
                                if (c == 'p') {
                                  c = str[11];
                                  if (c == 'a') {
                                    c = str[12];
                                    if (c == 'g') {
                                      c = str[13];
                                      if (c == 'e') {
                                        c = str[14];
                                        if (!c) return NEW_SRV_ACTION_REG_LOGIN_PAGE;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    } else if (c < 'l') {
                      if (c == 'd') {
                        c = str[5];
                        if (c == 'a') {
                          c = str[6];
                          if (c == 't') {
                            c = str[7];
                            if (c == 'a') {
                              c = str[8];
                              if (c == '-') {
                                c = str[9];
                                if (c == 'e') {
                                  c = str[10];
                                  if (c == 'd') {
                                    c = str[11];
                                    if (c == 'i') {
                                      c = str[12];
                                      if (c == 't') {
                                        c = str[13];
                                        if (!c) return NEW_SRV_ACTION_REG_DATA_EDIT;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      } else if (c < 'd') {
                        if (c == 'c') {
                          c = str[5];
                          if (c == 'r') {
                            c = str[6];
                            if (c == 'e') {
                              c = str[7];
                              if (c == 'a') {
                                c = str[8];
                                if (c == 't') {
                                  c = str[9];
                                  if (c == 'e') {
                                    c = str[10];
                                    if (c == '-') {
                                      c = str[11];
                                      if (c == 'a') {
                                        c = str[12];
                                        if (c == 'c') {
                                          c = str[13];
                                          if (c == 'c') {
                                            c = str[14];
                                            if (c == 'o') {
                                              c = str[15];
                                              if (c == 'u') {
                                                c = str[16];
                                                if (c == 'n') {
                                                  c = str[17];
                                                  if (c == 't') {
                                                    c = str[18];
                                                    if (!c) return NEW_SRV_ACTION_REG_CREATE_ACCOUNT;
                                                    if (c == '-') {
                                                      c = str[19];
                                                      if (c == 'p') {
                                                        c = str[20];
                                                        if (c == 'a') {
                                                          c = str[21];
                                                          if (c == 'g') {
                                                            c = str[22];
                                                            if (c == 'e') {
                                                              c = str[23];
                                                              if (!c) return NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE;
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 'r') {
                            if (c == 'a') {
                              c = str[6];
                              if (c == 'n') {
                                c = str[7];
                                if (c == 'c') {
                                  c = str[8];
                                  if (c == 'e') {
                                    c = str[9];
                                    if (c == 'l') {
                                      c = str[10];
                                      if (c == '-') {
                                        c = str[11];
                                        if (c == 'm') {
                                          c = str[12];
                                          if (c == 'e') {
                                            c = str[13];
                                            if (c == 'm') {
                                              c = str[14];
                                              if (c == 'b') {
                                                c = str[15];
                                                if (c == 'e') {
                                                  c = str[16];
                                                  if (c == 'r') {
                                                    c = str[17];
                                                    if (c == '-') {
                                                      c = str[18];
                                                      if (c == 'e') {
                                                        c = str[19];
                                                        if (c == 'd') {
                                                          c = str[20];
                                                          if (c == 'i') {
                                                            c = str[21];
                                                            if (c == 't') {
                                                              c = str[22];
                                                              if (c == 'i') {
                                                                c = str[23];
                                                                if (c == 'n') {
                                                                  c = str[24];
                                                                  if (c == 'g') {
                                                                    c = str[25];
                                                                    if (!c) return NEW_SRV_ACTION_REG_CANCEL_MEMBER_EDITING;
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        } else if (c < 'm') {
                                          if (c == 'g') {
                                            c = str[12];
                                            if (c == 'e') {
                                              c = str[13];
                                              if (c == 'n') {
                                                c = str[14];
                                                if (c == 'e') {
                                                  c = str[15];
                                                  if (c == 'r') {
                                                    c = str[16];
                                                    if (c == 'a') {
                                                      c = str[17];
                                                      if (c == 'l') {
                                                        c = str[18];
                                                        if (c == '-') {
                                                          c = str[19];
                                                          if (c == 'e') {
                                                            c = str[20];
                                                            if (c == 'd') {
                                                              c = str[21];
                                                              if (c == 'i') {
                                                                c = str[22];
                                                                if (c == 't') {
                                                                  c = str[23];
                                                                  if (c == 'i') {
                                                                    c = str[24];
                                                                    if (c == 'n') {
                                                                      c = str[25];
                                                                      if (c == 'g') {
                                                                        c = str[26];
                                                                        if (!c) return NEW_SRV_ACTION_REG_CANCEL_GENERAL_EDITING;
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                        } else {
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          } else {
                          }
                          return 0;
                        } else if (c < 'c') {
                          if (c == 'a') {
                            c = str[5];
                            if (c == 'd') {
                              c = str[6];
                              if (c == 'd') {
                                c = str[7];
                                if (c == '-') {
                                  c = str[8];
                                  if (c == 'm') {
                                    c = str[9];
                                    if (c == 'e') {
                                      c = str[10];
                                      if (c == 'm') {
                                        c = str[11];
                                        if (c == 'b') {
                                          c = str[12];
                                          if (c == 'e') {
                                            c = str[13];
                                            if (c == 'r') {
                                              c = str[14];
                                              if (c == '-') {
                                                c = str[15];
                                                if (c == 'p') {
                                                  c = str[16];
                                                  if (c == 'a') {
                                                    c = str[17];
                                                    if (c == 'g') {
                                                      c = str[18];
                                                      if (c == 'e') {
                                                        c = str[19];
                                                        if (!c) return NEW_SRV_ACTION_REG_ADD_MEMBER_PAGE;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            } else if (c < 'd') {
                              if (c == 'c') {
                                c = str[6];
                                if (c == 'c') {
                                  c = str[7];
                                  if (c == 'o') {
                                    c = str[8];
                                    if (c == 'u') {
                                      c = str[9];
                                      if (c == 'n') {
                                        c = str[10];
                                        if (c == 't') {
                                          c = str[11];
                                          if (c == '-') {
                                            c = str[12];
                                            if (c == 'c') {
                                              c = str[13];
                                              if (c == 'r') {
                                                c = str[14];
                                                if (c == 'e') {
                                                  c = str[15];
                                                  if (c == 'a') {
                                                    c = str[16];
                                                    if (c == 't') {
                                                      c = str[17];
                                                      if (c == 'e') {
                                                        c = str[18];
                                                        if (c == 'd') {
                                                          c = str[19];
                                                          if (c == '-') {
                                                            c = str[20];
                                                            if (c == 'p') {
                                                              c = str[21];
                                                              if (c == 'a') {
                                                                c = str[22];
                                                                if (c == 'g') {
                                                                  c = str[23];
                                                                  if (c == 'e') {
                                                                    c = str[24];
                                                                    if (!c) return NEW_SRV_ACTION_REG_ACCOUNT_CREATED_PAGE;
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                            } else {
                            }
                            return 0;
                          }
                        } else {
                        }
                      } else {
                        if (c == 'e') {
                          c = str[5];
                          if (c == 'd') {
                            c = str[6];
                            if (c == 'i') {
                              c = str[7];
                              if (c == 't') {
                                c = str[8];
                                if (c == '-') {
                                  c = str[9];
                                  if (c == 'm') {
                                    c = str[10];
                                    if (c == 'e') {
                                      c = str[11];
                                      if (c == 'm') {
                                        c = str[12];
                                        if (c == 'b') {
                                          c = str[13];
                                          if (c == 'e') {
                                            c = str[14];
                                            if (c == 'r') {
                                              c = str[15];
                                              if (c == '-') {
                                                c = str[16];
                                                if (c == 'p') {
                                                  c = str[17];
                                                  if (c == 'a') {
                                                    c = str[18];
                                                    if (c == 'g') {
                                                      c = str[19];
                                                      if (c == 'e') {
                                                        c = str[20];
                                                        if (!c) return NEW_SRV_ACTION_REG_EDIT_MEMBER_PAGE;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  } else if (c < 'm') {
                                    if (c == 'g') {
                                      c = str[10];
                                      if (c == 'e') {
                                        c = str[11];
                                        if (c == 'n') {
                                          c = str[12];
                                          if (c == 'e') {
                                            c = str[13];
                                            if (c == 'r') {
                                              c = str[14];
                                              if (c == 'a') {
                                                c = str[15];
                                                if (c == 'l') {
                                                  c = str[16];
                                                  if (c == '-') {
                                                    c = str[17];
                                                    if (c == 'p') {
                                                      c = str[18];
                                                      if (c == 'a') {
                                                        c = str[19];
                                                        if (c == 'g') {
                                                          c = str[20];
                                                          if (c == 'e') {
                                                            c = str[21];
                                                            if (!c) return NEW_SRV_ACTION_REG_EDIT_GENERAL_PAGE;
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                  } else {
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                      }
                    } else {
                      if (c == 's') {
                        c = str[5];
                        if (c == 'u') {
                          c = str[6];
                          if (c == 'b') {
                            c = str[7];
                            if (c == 'm') {
                              c = str[8];
                              if (c == 'i') {
                                c = str[9];
                                if (c == 't') {
                                  c = str[10];
                                  if (c == '-') {
                                    c = str[11];
                                    if (c == 'm') {
                                      c = str[12];
                                      if (c == 'e') {
                                        c = str[13];
                                        if (c == 'm') {
                                          c = str[14];
                                          if (c == 'b') {
                                            c = str[15];
                                            if (c == 'e') {
                                              c = str[16];
                                              if (c == 'r') {
                                                c = str[17];
                                                if (c == '-') {
                                                  c = str[18];
                                                  if (c == 'e') {
                                                    c = str[19];
                                                    if (c == 'd') {
                                                      c = str[20];
                                                      if (c == 'i') {
                                                        c = str[21];
                                                        if (c == 't') {
                                                          c = str[22];
                                                          if (c == 'i') {
                                                            c = str[23];
                                                            if (c == 'n') {
                                                              c = str[24];
                                                              if (c == 'g') {
                                                                c = str[25];
                                                                if (!c) return NEW_SRV_ACTION_REG_SUBMIT_MEMBER_EDITING;
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    } else if (c < 'm') {
                                      if (c == 'g') {
                                        c = str[12];
                                        if (c == 'e') {
                                          c = str[13];
                                          if (c == 'n') {
                                            c = str[14];
                                            if (c == 'e') {
                                              c = str[15];
                                              if (c == 'r') {
                                                c = str[16];
                                                if (c == 'a') {
                                                  c = str[17];
                                                  if (c == 'l') {
                                                    c = str[18];
                                                    if (c == '-') {
                                                      c = str[19];
                                                      if (c == 'e') {
                                                        c = str[20];
                                                        if (c == 'd') {
                                                          c = str[21];
                                                          if (c == 'i') {
                                                            c = str[22];
                                                            if (c == 't') {
                                                              c = str[23];
                                                              if (c == 'i') {
                                                                c = str[24];
                                                                if (c == 'n') {
                                                                  c = str[25];
                                                                  if (c == 'g') {
                                                                    c = str[26];
                                                                    if (!c) return NEW_SRV_ACTION_REG_SUBMIT_GENERAL_EDITING;
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                    } else {
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      } else if (c < 's') {
                        if (c == 'r') {
                          c = str[5];
                          if (c == 'e') {
                            c = str[6];
                            if (c == 'm') {
                              c = str[7];
                              if (c == 'o') {
                                c = str[8];
                                if (c == 'v') {
                                  c = str[9];
                                  if (c == 'e') {
                                    c = str[10];
                                    if (c == '-') {
                                      c = str[11];
                                      if (c == 'm') {
                                        c = str[12];
                                        if (c == 'e') {
                                          c = str[13];
                                          if (c == 'm') {
                                            c = str[14];
                                            if (c == 'b') {
                                              c = str[15];
                                              if (c == 'e') {
                                                c = str[16];
                                                if (c == 'r') {
                                                  c = str[17];
                                                  if (!c) return NEW_SRV_ACTION_REG_REMOVE_MEMBER;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            } else if (c < 'm') {
                              if (c == 'g') {
                                c = str[7];
                                if (c == 'i') {
                                  c = str[8];
                                  if (c == 's') {
                                    c = str[9];
                                    if (c == 't') {
                                      c = str[10];
                                      if (c == 'e') {
                                        c = str[11];
                                        if (c == 'r') {
                                          c = str[12];
                                          if (!c) return NEW_SRV_ACTION_REG_REGISTER;
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                            } else {
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 'r') {
                          if (c == 'm') {
                            c = str[5];
                            if (c == 'o') {
                              c = str[6];
                              if (c == 'v') {
                                c = str[7];
                                if (c == 'e') {
                                  c = str[8];
                                  if (c == '-') {
                                    c = str[9];
                                    if (c == 'm') {
                                      c = str[10];
                                      if (c == 'e') {
                                        c = str[11];
                                        if (c == 'm') {
                                          c = str[12];
                                          if (c == 'b') {
                                            c = str[13];
                                            if (c == 'e') {
                                              c = str[14];
                                              if (c == 'r') {
                                                c = str[15];
                                                if (!c) return NEW_SRV_ACTION_REG_MOVE_MEMBER;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                        } else {
                        }
                      } else {
                        if (c == 'v') {
                          c = str[5];
                          if (c == 'i') {
                            c = str[6];
                            if (c == 'e') {
                              c = str[7];
                              if (c == 'w') {
                                c = str[8];
                                if (c == '-') {
                                  c = str[9];
                                  if (c == 'g') {
                                    c = str[10];
                                    if (c == 'u') {
                                      c = str[11];
                                      if (c == 'e') {
                                        c = str[12];
                                        if (c == 's') {
                                          c = str[13];
                                          if (c == 't') {
                                            c = str[14];
                                            if (c == 's') {
                                              c = str[15];
                                              if (!c) return NEW_SRV_ACTION_REG_VIEW_GUESTS;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    } else if (c < 'u') {
                                      if (c == 'e') {
                                        c = str[11];
                                        if (c == 'n') {
                                          c = str[12];
                                          if (c == 'e') {
                                            c = str[13];
                                            if (c == 'r') {
                                              c = str[14];
                                              if (c == 'a') {
                                                c = str[15];
                                                if (c == 'l') {
                                                  c = str[16];
                                                  if (!c) return NEW_SRV_ACTION_REG_VIEW_GENERAL;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                    } else {
                                    }
                                    return 0;
                                  } else if (c < 'g') {
                                    if (c == 'c') {
                                      c = str[10];
                                      if (c == 'o') {
                                        c = str[11];
                                        if (c == 'n') {
                                          c = str[12];
                                          if (c == 't') {
                                            c = str[13];
                                            if (c == 'e') {
                                              c = str[14];
                                              if (c == 's') {
                                                c = str[15];
                                                if (c == 't') {
                                                  c = str[16];
                                                  if (c == 'a') {
                                                    c = str[17];
                                                    if (c == 'n') {
                                                      c = str[18];
                                                      if (c == 't') {
                                                        c = str[19];
                                                        if (c == 's') {
                                                          c = str[20];
                                                          if (!c) return NEW_SRV_ACTION_REG_VIEW_CONTESTANTS;
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        } else if (c < 'n') {
                                          if (c == 'a') {
                                            c = str[12];
                                            if (c == 'c') {
                                              c = str[13];
                                              if (c == 'h') {
                                                c = str[14];
                                                if (c == 'e') {
                                                  c = str[15];
                                                  if (c == 's') {
                                                    c = str[16];
                                                    if (!c) return NEW_SRV_ACTION_REG_VIEW_COACHES;
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                        } else {
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    } else if (c < 'c') {
                                      if (c == 'a') {
                                        c = str[10];
                                        if (c == 'd') {
                                          c = str[11];
                                          if (c == 'v') {
                                            c = str[12];
                                            if (c == 'i') {
                                              c = str[13];
                                              if (c == 's') {
                                                c = str[14];
                                                if (c == 'o') {
                                                  c = str[15];
                                                  if (c == 'r') {
                                                    c = str[16];
                                                    if (c == 's') {
                                                      c = str[17];
                                                      if (!c) return NEW_SRV_ACTION_REG_VIEW_ADVISORS;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                    } else {
                                    }
                                  } else {
                                    if (c == 'r') {
                                      c = str[10];
                                      if (c == 'e') {
                                        c = str[11];
                                        if (c == 's') {
                                          c = str[12];
                                          if (c == 'e') {
                                            c = str[13];
                                            if (c == 'r') {
                                              c = str[14];
                                              if (c == 'v') {
                                                c = str[15];
                                                if (c == 'e') {
                                                  c = str[16];
                                                  if (c == 's') {
                                                    c = str[17];
                                                    if (!c) return NEW_SRV_ACTION_REG_VIEW_RESERVES;
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                      }
                    }
                    return 0;
                  }
                  return 0;
                }
              } else {
              }
            } else {
              if (c == 's') {
                c = str[3];
                if (c == 'u') {
                  c = str[4];
                  if (c == 'm') {
                    c = str[5];
                    if (c == 'e') {
                      c = str[6];
                      if (!c) return NEW_SRV_ACTION_RESUME;
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                } else if (c < 'u') {
                  if (c == 'e') {
                    c = str[4];
                    if (c == 't') {
                      c = str[5];
                      if (c == '-') {
                        c = str[6];
                        if (c == 'c') {
                          c = str[7];
                          if (c == 'l') {
                            c = str[8];
                            if (c == 'a') {
                              c = str[9];
                              if (c == 'r') {
                                c = str[10];
                                if (c == '-') {
                                  c = str[11];
                                  if (c == 'f') {
                                    c = str[12];
                                    if (c == 'i') {
                                      c = str[13];
                                      if (c == 'l') {
                                        c = str[14];
                                        if (c == 't') {
                                          c = str[15];
                                          if (c == 'e') {
                                            c = str[16];
                                            if (c == 'r') {
                                              c = str[17];
                                              if (!c) return NEW_SRV_ACTION_RESET_CLAR_FILTER;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 'c') {
                          if (c == '2') {
                            c = str[7];
                            if (!c) return NEW_SRV_ACTION_RESET_2;
                            return 0;
                          } else if (c < '2') {
                            if (c == '1') {
                              c = str[7];
                              if (!c) return NEW_SRV_ACTION_RESET_1;
                              return 0;
                            }
                          } else {
                          }
                        } else {
                          if (c == 's') {
                            c = str[7];
                            if (c == 't') {
                              c = str[8];
                              if (c == 'a') {
                                c = str[9];
                                if (c == 'n') {
                                  c = str[10];
                                  if (c == 'd') {
                                    c = str[11];
                                    if (c == '-') {
                                      c = str[12];
                                      if (c == 'f') {
                                        c = str[13];
                                        if (c == 'i') {
                                          c = str[14];
                                          if (c == 'l') {
                                            c = str[15];
                                            if (c == 't') {
                                              c = str[16];
                                              if (c == 'e') {
                                                c = str[17];
                                                if (c == 'r') {
                                                  c = str[18];
                                                  if (!c) return NEW_SRV_ACTION_RESET_STAND_FILTER;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 's') {
                            if (c == 'f') {
                              c = str[7];
                              if (c == 'i') {
                                c = str[8];
                                if (c == 'l') {
                                  c = str[9];
                                  if (c == 't') {
                                    c = str[10];
                                    if (c == 'e') {
                                      c = str[11];
                                      if (c == 'r') {
                                        c = str[12];
                                        if (!c) return NEW_SRV_ACTION_RESET_FILTER;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          } else {
                          }
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                } else {
                }
                return 0;
              } else if (c < 's') {
                if (c == 'm') {
                  c = str[3];
                  if (c == 'o') {
                    c = str[4];
                    if (c == 'v') {
                      c = str[5];
                      if (c == 'e') {
                        c = str[6];
                        if (c == '-') {
                          c = str[7];
                          if (c == 'u') {
                            c = str[8];
                            if (c == 's') {
                              c = str[9];
                              if (c == 'e') {
                                c = str[10];
                                if (c == 'r') {
                                  c = str[11];
                                  if (c == 'p') {
                                    c = str[12];
                                    if (c == 'r') {
                                      c = str[13];
                                      if (c == 'o') {
                                        c = str[14];
                                        if (c == 'b') {
                                          c = str[15];
                                          if (!c) return NEW_SRV_ACTION_REMOVE_USERPROB;
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
              } else {
              }
            }
            return 0;
          } else if (c < 'e') {
            if (c == 'a') {
              c = str[2];
              if (c == 'w') {
                c = str[3];
                if (c == '-') {
                  c = str[4];
                  if (c == 'r') {
                    c = str[5];
                    if (c == 'e') {
                      c = str[6];
                      if (c == 'p') {
                        c = str[7];
                        if (c == 'o') {
                          c = str[8];
                          if (c == 'r') {
                            c = str[9];
                            if (c == 't') {
                              c = str[10];
                              if (!c) return NEW_SRV_ACTION_RAW_REPORT;
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  } else if (c < 'r') {
                    if (c == 'a') {
                      c = str[5];
                      if (c == 'u') {
                        c = str[6];
                        if (c == 'd') {
                          c = str[7];
                          if (c == 'i') {
                            c = str[8];
                            if (c == 't') {
                              c = str[9];
                              if (c == '-') {
                                c = str[10];
                                if (c == 'l') {
                                  c = str[11];
                                  if (c == 'o') {
                                    c = str[12];
                                    if (c == 'g') {
                                      c = str[13];
                                      if (!c) return NEW_SRV_ACTION_RAW_AUDIT_LOG;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                  } else {
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
          } else {
            if (c == 'u') {
              c = str[2];
              if (c == 'n') {
                c = str[3];
                if (c == '-') {
                  c = str[4];
                  if (c == 's') {
                    c = str[5];
                    if (c == 't') {
                      c = str[6];
                      if (c == 'a') {
                        c = str[7];
                        if (c == 't') {
                          c = str[8];
                          if (c == 'u') {
                            c = str[9];
                            if (c == 's') {
                              c = str[10];
                              if (c == '-') {
                                c = str[11];
                                if (c == 'j') {
                                  c = str[12];
                                  if (c == 's') {
                                    c = str[13];
                                    if (c == 'o') {
                                      c = str[14];
                                      if (c == 'n') {
                                        c = str[15];
                                        if (!c) return NEW_SRV_ACTION_RUN_STATUS_JSON;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  } else if (c < 's') {
                    if (c == 'm') {
                      c = str[5];
                      if (c == 'e') {
                        c = str[6];
                        if (c == 's') {
                          c = str[7];
                          if (c == 's') {
                            c = str[8];
                            if (c == 'a') {
                              c = str[9];
                              if (c == 'g') {
                                c = str[10];
                                if (c == 'e') {
                                  c = str[11];
                                  if (c == 's') {
                                    c = str[12];
                                    if (c == '-') {
                                      c = str[13];
                                      if (c == 'j') {
                                        c = str[14];
                                        if (c == 's') {
                                          c = str[15];
                                          if (c == 'o') {
                                            c = str[16];
                                            if (c == 'n') {
                                              c = str[17];
                                              if (!c) return NEW_SRV_ACTION_RUN_MESSAGES_JSON;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                  } else {
                    if (c == 't') {
                      c = str[5];
                      if (c == 'e') {
                        c = str[6];
                        if (c == 's') {
                          c = str[7];
                          if (c == 't') {
                            c = str[8];
                            if (c == '-') {
                              c = str[9];
                              if (c == 'j') {
                                c = str[10];
                                if (c == 's') {
                                  c = str[11];
                                  if (c == 'o') {
                                    c = str[12];
                                    if (c == 'n') {
                                      c = str[13];
                                      if (!c) return NEW_SRV_ACTION_RUN_TEST_JSON;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
          }
          return 0;
        } else if (c < 'r') {
          if (c == 'p') {
            c = str[1];
            if (c == 'r') {
              c = str[2];
              if (c == 'o') {
                c = str[3];
                if (c == 'b') {
                  c = str[4];
                  if (c == 'l') {
                    c = str[5];
                    if (c == 'e') {
                      c = str[6];
                      if (c == 'm') {
                        c = str[7];
                        if (c == '-') {
                          c = str[8];
                          if (c == 's') {
                            c = str[9];
                            if (c == 't') {
                              c = str[10];
                              if (c == 'a') {
                                c = str[11];
                                if (c == 't') {
                                  c = str[12];
                                  if (c == 's') {
                                    c = str[13];
                                    if (c == '-') {
                                      c = str[14];
                                      if (c == 'p') {
                                        c = str[15];
                                        if (c == 'a') {
                                          c = str[16];
                                          if (c == 'g') {
                                            c = str[17];
                                            if (c == 'e') {
                                              c = str[18];
                                              if (!c) return NEW_SRV_ACTION_PROBLEM_STATS_PAGE;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  } else if (c < 's') {
                                    if (c == 'e') {
                                      c = str[13];
                                      if (c == 'm') {
                                        c = str[14];
                                        if (c == 'e') {
                                          c = str[15];
                                          if (c == 'n') {
                                            c = str[16];
                                            if (c == 't') {
                                              c = str[17];
                                              if (c == '-') {
                                                c = str[18];
                                                if (c == 'j') {
                                                  c = str[19];
                                                  if (c == 's') {
                                                    c = str[20];
                                                    if (c == 'o') {
                                                      c = str[21];
                                                      if (c == 'n') {
                                                        c = str[22];
                                                        if (!c) return NEW_SRV_ACTION_PROBLEM_STATEMENT_JSON;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                  } else {
                                    if (c == 'u') {
                                      c = str[13];
                                      if (c == 's') {
                                        c = str[14];
                                        if (c == '-') {
                                          c = str[15];
                                          if (c == 'j') {
                                            c = str[16];
                                            if (c == 's') {
                                              c = str[17];
                                              if (c == 'o') {
                                                c = str[18];
                                                if (c == 'n') {
                                                  c = str[19];
                                                  if (!c) return NEW_SRV_ACTION_PROBLEM_STATUS_JSON;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              } else if (c < 'o') {
                if (c == 'i') {
                  c = str[3];
                  if (c == 'o') {
                    c = str[4];
                    if (c == '-') {
                      c = str[5];
                      if (c == 'f') {
                        c = str[6];
                        if (c == 'o') {
                          c = str[7];
                          if (c == 'r') {
                            c = str[8];
                            if (c == 'm') {
                              c = str[9];
                              if (!c) return NEW_SRV_ACTION_PRIO_FORM;
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  } else if (c < 'o') {
                    if (c == 'n') {
                      c = str[4];
                      if (c == 't') {
                        c = str[5];
                        if (c == '-') {
                          c = str[6];
                          if (c == 's') {
                            c = str[7];
                            if (c == 'u') {
                              c = str[8];
                              if (c == 's') {
                                c = str[9];
                                if (c == 'p') {
                                  c = str[10];
                                  if (c == 'e') {
                                    c = str[11];
                                    if (c == 'n') {
                                      c = str[12];
                                      if (c == 'd') {
                                        c = str[13];
                                        if (!c) return NEW_SRV_ACTION_PRINT_SUSPEND;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            } else if (c < 'u') {
                              if (c == 'e') {
                                c = str[8];
                                if (c == 'l') {
                                  c = str[9];
                                  if (c == 'e') {
                                    c = str[10];
                                    if (c == 'c') {
                                      c = str[11];
                                      if (c == 't') {
                                        c = str[12];
                                        if (c == 'e') {
                                          c = str[13];
                                          if (c == 'd') {
                                            c = str[14];
                                            if (c == '-') {
                                              c = str[15];
                                              if (c == 'u') {
                                                c = str[16];
                                                if (c == 's') {
                                                  c = str[17];
                                                  if (c == 'e') {
                                                    c = str[18];
                                                    if (c == 'r') {
                                                      c = str[19];
                                                      if (c == '-') {
                                                        c = str[20];
                                                        if (c == 'p') {
                                                          c = str[21];
                                                          if (c == 'r') {
                                                            c = str[22];
                                                            if (c == 'o') {
                                                              c = str[23];
                                                              if (c == 't') {
                                                                c = str[24];
                                                                if (c == 'o') {
                                                                  c = str[25];
                                                                  if (c == 'c') {
                                                                    c = str[26];
                                                                    if (c == 'o') {
                                                                      c = str[27];
                                                                      if (c == 'l') {
                                                                        c = str[28];
                                                                        if (!c) return NEW_SRV_ACTION_PRINT_SELECTED_USER_PROTOCOL;
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        } else if (c < 'p') {
                                                          if (c == 'f') {
                                                            c = str[21];
                                                            if (c == 'u') {
                                                              c = str[22];
                                                              if (c == 'l') {
                                                                c = str[23];
                                                                if (c == 'l') {
                                                                  c = str[24];
                                                                  if (c == '-') {
                                                                    c = str[25];
                                                                    if (c == 'p') {
                                                                      c = str[26];
                                                                      if (c == 'r') {
                                                                        c = str[27];
                                                                        if (c == 'o') {
                                                                          c = str[28];
                                                                          if (c == 't') {
                                                                            c = str[29];
                                                                            if (c == 'o') {
                                                                              c = str[30];
                                                                              if (c == 'c') {
                                                                                c = str[31];
                                                                                if (c == 'o') {
                                                                                  c = str[32];
                                                                                  if (c == 'l') {
                                                                                    c = str[33];
                                                                                    if (!c) return NEW_SRV_ACTION_PRINT_SELECTED_USER_FULL_PROTOCOL;
                                                                                    return 0;
                                                                                  }
                                                                                  return 0;
                                                                                }
                                                                                return 0;
                                                                              }
                                                                              return 0;
                                                                            }
                                                                            return 0;
                                                                          }
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                        } else {
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                } else if (c < 's') {
                                                  if (c == 'f') {
                                                    c = str[17];
                                                    if (c == 'c') {
                                                      c = str[18];
                                                      if (c == '-') {
                                                        c = str[19];
                                                        if (c == 'p') {
                                                          c = str[20];
                                                          if (c == 'r') {
                                                            c = str[21];
                                                            if (c == 'o') {
                                                              c = str[22];
                                                              if (c == 't') {
                                                                c = str[23];
                                                                if (c == 'o') {
                                                                  c = str[24];
                                                                  if (c == 'c') {
                                                                    c = str[25];
                                                                    if (c == 'o') {
                                                                      c = str[26];
                                                                      if (c == 'l') {
                                                                        c = str[27];
                                                                        if (!c) return NEW_SRV_ACTION_PRINT_SELECTED_UFC_PROTOCOL;
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                } else {
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                            } else {
                            }
                            return 0;
                          } else if (c < 's') {
                            if (c == 'r') {
                              c = str[7];
                              if (c == 'u') {
                                c = str[8];
                                if (c == 'n') {
                                  c = str[9];
                                  if (!c) return NEW_SRV_ACTION_PRINT_RUN;
                                  return 0;
                                }
                                return 0;
                              } else if (c < 'u') {
                                if (c == 'e') {
                                  c = str[8];
                                  if (c == 's') {
                                    c = str[9];
                                    if (c == 'u') {
                                      c = str[10];
                                      if (c == 'm') {
                                        c = str[11];
                                        if (c == 'e') {
                                          c = str[12];
                                          if (!c) return NEW_SRV_ACTION_PRINT_RESUME;
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                              } else {
                              }
                              return 0;
                            } else if (c < 'r') {
                              if (c == 'p') {
                                c = str[7];
                                if (c == 'r') {
                                  c = str[8];
                                  if (c == 'o') {
                                    c = str[9];
                                    if (c == 'b') {
                                      c = str[10];
                                      if (c == 'l') {
                                        c = str[11];
                                        if (c == 'e') {
                                          c = str[12];
                                          if (c == 'm') {
                                            c = str[13];
                                            if (c == '-') {
                                              c = str[14];
                                              if (c == 'p') {
                                                c = str[15];
                                                if (c == 'r') {
                                                  c = str[16];
                                                  if (c == 'o') {
                                                    c = str[17];
                                                    if (c == 't') {
                                                      c = str[18];
                                                      if (c == 'o') {
                                                        c = str[19];
                                                        if (c == 'c') {
                                                          c = str[20];
                                                          if (c == 'o') {
                                                            c = str[21];
                                                            if (c == 'l') {
                                                              c = str[22];
                                                              if (!c) return NEW_SRV_ACTION_PRINT_PROBLEM_PROTOCOL;
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                            } else {
                            }
                          } else {
                            if (c == 'u') {
                              c = str[7];
                              if (c == 's') {
                                c = str[8];
                                if (c == 'e') {
                                  c = str[9];
                                  if (c == 'r') {
                                    c = str[10];
                                    if (c == '-') {
                                      c = str[11];
                                      if (c == 'p') {
                                        c = str[12];
                                        if (c == 'r') {
                                          c = str[13];
                                          if (c == 'o') {
                                            c = str[14];
                                            if (c == 't') {
                                              c = str[15];
                                              if (c == 'o') {
                                                c = str[16];
                                                if (c == 'c') {
                                                  c = str[17];
                                                  if (c == 'o') {
                                                    c = str[18];
                                                    if (c == 'l') {
                                                      c = str[19];
                                                      if (!c) return NEW_SRV_ACTION_PRINT_USER_PROTOCOL;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      } else if (c < 'p') {
                                        if (c == 'f') {
                                          c = str[12];
                                          if (c == 'u') {
                                            c = str[13];
                                            if (c == 'l') {
                                              c = str[14];
                                              if (c == 'l') {
                                                c = str[15];
                                                if (c == '-') {
                                                  c = str[16];
                                                  if (c == 'p') {
                                                    c = str[17];
                                                    if (c == 'r') {
                                                      c = str[18];
                                                      if (c == 'o') {
                                                        c = str[19];
                                                        if (c == 't') {
                                                          c = str[20];
                                                          if (c == 'o') {
                                                            c = str[21];
                                                            if (c == 'c') {
                                                              c = str[22];
                                                              if (c == 'o') {
                                                                c = str[23];
                                                                if (c == 'l') {
                                                                  c = str[24];
                                                                  if (!c) return NEW_SRV_ACTION_PRINT_USER_FULL_PROTOCOL;
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                      } else {
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              } else if (c < 's') {
                                if (c == 'f') {
                                  c = str[8];
                                  if (c == 'c') {
                                    c = str[9];
                                    if (c == '-') {
                                      c = str[10];
                                      if (c == 'p') {
                                        c = str[11];
                                        if (c == 'r') {
                                          c = str[12];
                                          if (c == 'o') {
                                            c = str[13];
                                            if (c == 't') {
                                              c = str[14];
                                              if (c == 'o') {
                                                c = str[15];
                                                if (c == 'c') {
                                                  c = str[16];
                                                  if (c == 'o') {
                                                    c = str[17];
                                                    if (c == 'l') {
                                                      c = str[18];
                                                      if (!c) return NEW_SRV_ACTION_PRINT_UFC_PROTOCOL;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                              } else {
                              }
                              return 0;
                            }
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                  } else {
                    if (c == 'v') {
                      c = str[4];
                      if (c == '-') {
                        c = str[5];
                        if (c == 'r') {
                          c = str[6];
                          if (c == 'e') {
                            c = str[7];
                            if (c == 'g') {
                              c = str[8];
                              if (c == 'e') {
                                c = str[9];
                                if (c == 'n') {
                                  c = str[10];
                                  if (c == 'e') {
                                    c = str[11];
                                    if (c == 'r') {
                                      c = str[12];
                                      if (c == 'a') {
                                        c = str[13];
                                        if (c == 't') {
                                          c = str[14];
                                          if (c == 'e') {
                                            c = str[15];
                                            if (c == '-') {
                                              c = str[16];
                                              if (c == 'c') {
                                                c = str[17];
                                                if (c == 'o') {
                                                  c = str[18];
                                                  if (c == 'n') {
                                                    c = str[19];
                                                    if (c == 't') {
                                                      c = str[20];
                                                      if (c == 'e') {
                                                        c = str[21];
                                                        if (c == 'n') {
                                                          c = str[22];
                                                          if (c == 't') {
                                                            c = str[23];
                                                            if (!c) return NEW_SRV_ACTION_PRIV_REGENERATE_CONTENT;
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 'r') {
                          if (c == 'o') {
                            c = str[6];
                            if (c == 'l') {
                              c = str[7];
                              if (c == 'd') {
                                c = str[8];
                                if (c == '-') {
                                  c = str[9];
                                  if (c == 's') {
                                    c = str[10];
                                    if (c == 'e') {
                                      c = str[11];
                                      if (c == 't') {
                                        c = str[12];
                                        if (c == '-') {
                                          c = str[13];
                                          if (c == 'r') {
                                            c = str[14];
                                            if (c == 'u') {
                                              c = str[15];
                                              if (c == 'n') {
                                                c = str[16];
                                                if (c == '-') {
                                                  c = str[17];
                                                  if (c == 'r') {
                                                    c = str[18];
                                                    if (c == 'e') {
                                                      c = str[19];
                                                      if (c == 'j') {
                                                        c = str[20];
                                                        if (c == 'e') {
                                                          c = str[21];
                                                          if (c == 'c') {
                                                            c = str[22];
                                                            if (c == 't') {
                                                              c = str[23];
                                                              if (c == 'e') {
                                                                c = str[24];
                                                                if (c == 'd') {
                                                                  c = str[25];
                                                                  if (!c) return NEW_SRV_ACTION_PRIV_OLD_SET_RUN_REJECTED;
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 'o') {
                            if (c == 'e') {
                              c = str[6];
                              if (c == 'd') {
                                c = str[7];
                                if (c == 'i') {
                                  c = str[8];
                                  if (c == 't') {
                                    c = str[9];
                                    if (c == '-') {
                                      c = str[10];
                                      if (c == 'r') {
                                        c = str[11];
                                        if (c == 'u') {
                                          c = str[12];
                                          if (c == 'n') {
                                            c = str[13];
                                            if (c == '-') {
                                              c = str[14];
                                              if (c == 'p') {
                                                c = str[15];
                                                if (c == 'a') {
                                                  c = str[16];
                                                  if (c == 'g') {
                                                    c = str[17];
                                                    if (c == 'e') {
                                                      c = str[18];
                                                      if (!c) return NEW_SRV_ACTION_PRIV_EDIT_RUN_PAGE;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              } else if (c < 'p') {
                                                if (c == 'a') {
                                                  c = str[15];
                                                  if (c == 'c') {
                                                    c = str[16];
                                                    if (c == 't') {
                                                      c = str[17];
                                                      if (c == 'i') {
                                                        c = str[18];
                                                        if (c == 'o') {
                                                          c = str[19];
                                                          if (c == 'n') {
                                                            c = str[20];
                                                            if (!c) return NEW_SRV_ACTION_PRIV_EDIT_RUN_ACTION;
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                              } else {
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      } else if (c < 'r') {
                                        if (c == 'c') {
                                          c = str[11];
                                          if (c == 'l') {
                                            c = str[12];
                                            if (c == 'a') {
                                              c = str[13];
                                              if (c == 'r') {
                                                c = str[14];
                                                if (c == '-') {
                                                  c = str[15];
                                                  if (c == 'p') {
                                                    c = str[16];
                                                    if (c == 'a') {
                                                      c = str[17];
                                                      if (c == 'g') {
                                                        c = str[18];
                                                        if (c == 'e') {
                                                          c = str[19];
                                                          if (!c) return NEW_SRV_ACTION_PRIV_EDIT_CLAR_PAGE;
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  } else if (c < 'p') {
                                                    if (c == 'a') {
                                                      c = str[16];
                                                      if (c == 'c') {
                                                        c = str[17];
                                                        if (c == 't') {
                                                          c = str[18];
                                                          if (c == 'i') {
                                                            c = str[19];
                                                            if (c == 'o') {
                                                              c = str[20];
                                                              if (c == 'n') {
                                                                c = str[21];
                                                                if (!c) return NEW_SRV_ACTION_PRIV_EDIT_CLAR_ACTION;
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                  } else {
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                      } else {
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          } else {
                          }
                        } else {
                          if (c == 'u') {
                            c = str[6];
                            if (c == 's') {
                              c = str[7];
                              if (c == 'e') {
                                c = str[8];
                                if (c == 'r') {
                                  c = str[9];
                                  if (c == 's') {
                                    c = str[10];
                                    if (c == '-') {
                                      c = str[11];
                                      if (c == 'r') {
                                        c = str[12];
                                        if (c == 'e') {
                                          c = str[13];
                                          if (c == 'm') {
                                            c = str[14];
                                            if (c == 'o') {
                                              c = str[15];
                                              if (c == 'v') {
                                                c = str[16];
                                                if (c == 'e') {
                                                  c = str[17];
                                                  if (!c) return NEW_SRV_ACTION_PRIV_USERS_REMOVE;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      } else if (c < 'r') {
                                        if (c == 'd') {
                                          c = str[12];
                                          if (c == 'e') {
                                            c = str[13];
                                            if (c == 'l') {
                                              c = str[14];
                                              if (c == '-') {
                                                c = str[15];
                                                if (c == 'e') {
                                                  c = str[16];
                                                  if (c == 'x') {
                                                    c = str[17];
                                                    if (c == 'a') {
                                                      c = str[18];
                                                      if (c == 'm') {
                                                        c = str[19];
                                                        if (c == 'i') {
                                                          c = str[20];
                                                          if (c == 'n') {
                                                            c = str[21];
                                                            if (c == 'e') {
                                                              c = str[22];
                                                              if (c == 'r') {
                                                                c = str[23];
                                                                if (!c) return NEW_SRV_ACTION_PRIV_USERS_DEL_EXAMINER;
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                } else if (c < 'e') {
                                                  if (c == 'c') {
                                                    c = str[16];
                                                    if (c == 'o') {
                                                      c = str[17];
                                                      if (c == 'o') {
                                                        c = str[18];
                                                        if (c == 'r') {
                                                          c = str[19];
                                                          if (c == 'd') {
                                                            c = str[20];
                                                            if (c == 'i') {
                                                              c = str[21];
                                                              if (c == 'n') {
                                                                c = str[22];
                                                                if (c == 'a') {
                                                                  c = str[23];
                                                                  if (c == 't') {
                                                                    c = str[24];
                                                                    if (c == 'o') {
                                                                      c = str[25];
                                                                      if (c == 'r') {
                                                                        c = str[26];
                                                                        if (!c) return NEW_SRV_ACTION_PRIV_USERS_DEL_COORDINATOR;
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    } else if (c < 'o') {
                                                      if (c == 'h') {
                                                        c = str[17];
                                                        if (c == 'i') {
                                                          c = str[18];
                                                          if (c == 'e') {
                                                            c = str[19];
                                                            if (c == 'f') {
                                                              c = str[20];
                                                              if (c == '-') {
                                                                c = str[21];
                                                                if (c == 'e') {
                                                                  c = str[22];
                                                                  if (c == 'x') {
                                                                    c = str[23];
                                                                    if (c == 'a') {
                                                                      c = str[24];
                                                                      if (c == 'm') {
                                                                        c = str[25];
                                                                        if (c == 'i') {
                                                                          c = str[26];
                                                                          if (c == 'n') {
                                                                            c = str[27];
                                                                            if (c == 'e') {
                                                                              c = str[28];
                                                                              if (c == 'r') {
                                                                                c = str[29];
                                                                                if (!c) return NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_EXAMINER;
                                                                                return 0;
                                                                              }
                                                                              return 0;
                                                                            }
                                                                            return 0;
                                                                          }
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                    } else {
                                                    }
                                                    return 0;
                                                  }
                                                } else {
                                                  if (c == 'o') {
                                                    c = str[16];
                                                    if (c == 'b') {
                                                      c = str[17];
                                                      if (c == 's') {
                                                        c = str[18];
                                                        if (c == 'e') {
                                                          c = str[19];
                                                          if (c == 'r') {
                                                            c = str[20];
                                                            if (c == 'v') {
                                                              c = str[21];
                                                              if (c == 'e') {
                                                                c = str[22];
                                                                if (c == 'r') {
                                                                  c = str[23];
                                                                  if (!c) return NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER;
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        } else if (c < 'd') {
                                          if (c == 'a') {
                                            c = str[12];
                                            if (c == 'd') {
                                              c = str[13];
                                              if (c == 'd') {
                                                c = str[14];
                                                if (c == '-') {
                                                  c = str[15];
                                                  if (c == 'e') {
                                                    c = str[16];
                                                    if (c == 'x') {
                                                      c = str[17];
                                                      if (c == 'a') {
                                                        c = str[18];
                                                        if (c == 'm') {
                                                          c = str[19];
                                                          if (c == 'i') {
                                                            c = str[20];
                                                            if (c == 'n') {
                                                              c = str[21];
                                                              if (c == 'e') {
                                                                c = str[22];
                                                                if (c == 'r') {
                                                                  c = str[23];
                                                                  if (!c) return NEW_SRV_ACTION_PRIV_USERS_ADD_EXAMINER;
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  } else if (c < 'e') {
                                                    if (c == 'c') {
                                                      c = str[16];
                                                      if (c == 'o') {
                                                        c = str[17];
                                                        if (c == 'o') {
                                                          c = str[18];
                                                          if (c == 'r') {
                                                            c = str[19];
                                                            if (c == 'd') {
                                                              c = str[20];
                                                              if (c == 'i') {
                                                                c = str[21];
                                                                if (c == 'n') {
                                                                  c = str[22];
                                                                  if (c == 'a') {
                                                                    c = str[23];
                                                                    if (c == 't') {
                                                                      c = str[24];
                                                                      if (c == 'o') {
                                                                        c = str[25];
                                                                        if (c == 'r') {
                                                                          c = str[26];
                                                                          if (!c) return NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR;
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      } else if (c < 'o') {
                                                        if (c == 'h') {
                                                          c = str[17];
                                                          if (c == 'i') {
                                                            c = str[18];
                                                            if (c == 'e') {
                                                              c = str[19];
                                                              if (c == 'f') {
                                                                c = str[20];
                                                                if (c == '-') {
                                                                  c = str[21];
                                                                  if (c == 'e') {
                                                                    c = str[22];
                                                                    if (c == 'x') {
                                                                      c = str[23];
                                                                      if (c == 'a') {
                                                                        c = str[24];
                                                                        if (c == 'm') {
                                                                          c = str[25];
                                                                          if (c == 'i') {
                                                                            c = str[26];
                                                                            if (c == 'n') {
                                                                              c = str[27];
                                                                              if (c == 'e') {
                                                                                c = str[28];
                                                                                if (c == 'r') {
                                                                                  c = str[29];
                                                                                  if (!c) return NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_EXAMINER;
                                                                                  return 0;
                                                                                }
                                                                                return 0;
                                                                              }
                                                                              return 0;
                                                                            }
                                                                            return 0;
                                                                          }
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                      } else {
                                                      }
                                                      return 0;
                                                    } else if (c < 'c') {
                                                      if (c == 'b') {
                                                        c = str[16];
                                                        if (c == 'y') {
                                                          c = str[17];
                                                          if (c == '-') {
                                                            c = str[18];
                                                            if (c == 'u') {
                                                              c = str[19];
                                                              if (c == 's') {
                                                                c = str[20];
                                                                if (c == 'e') {
                                                                  c = str[21];
                                                                  if (c == 'r') {
                                                                    c = str[22];
                                                                    if (c == '-') {
                                                                      c = str[23];
                                                                      if (c == 'i') {
                                                                        c = str[24];
                                                                        if (c == 'd') {
                                                                          c = str[25];
                                                                          if (!c) return NEW_SRV_ACTION_PRIV_USERS_ADD_BY_USER_ID;
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            } else if (c < 'u') {
                                                              if (c == 'l') {
                                                                c = str[19];
                                                                if (c == 'o') {
                                                                  c = str[20];
                                                                  if (c == 'g') {
                                                                    c = str[21];
                                                                    if (c == 'i') {
                                                                      c = str[22];
                                                                      if (c == 'n') {
                                                                        c = str[23];
                                                                        if (!c) return NEW_SRV_ACTION_PRIV_USERS_ADD_BY_LOGIN;
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                            } else {
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                    } else {
                                                    }
                                                  } else {
                                                    if (c == 'o') {
                                                      c = str[16];
                                                      if (c == 'b') {
                                                        c = str[17];
                                                        if (c == 's') {
                                                          c = str[18];
                                                          if (c == 'e') {
                                                            c = str[19];
                                                            if (c == 'r') {
                                                              c = str[20];
                                                              if (c == 'v') {
                                                                c = str[21];
                                                                if (c == 'e') {
                                                                  c = str[22];
                                                                  if (c == 'r') {
                                                                    c = str[23];
                                                                    if (!c) return NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER;
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                        } else {
                                        }
                                      } else {
                                        if (c == 'v') {
                                          c = str[12];
                                          if (c == 'i') {
                                            c = str[13];
                                            if (c == 'e') {
                                              c = str[14];
                                              if (c == 'w') {
                                                c = str[15];
                                                if (!c) return NEW_SRV_ACTION_PRIV_USERS_VIEW;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 'u') {
                            if (c == 's') {
                              c = str[6];
                              if (c == 'u') {
                                c = str[7];
                                if (c == 'b') {
                                  c = str[8];
                                  if (c == 'm') {
                                    c = str[9];
                                    if (c == 'i') {
                                      c = str[10];
                                      if (c == 't') {
                                        c = str[11];
                                        if (c == '-') {
                                          c = str[12];
                                          if (c == 'p') {
                                            c = str[13];
                                            if (c == 'a') {
                                              c = str[14];
                                              if (c == 'g') {
                                                c = str[15];
                                                if (c == 'e') {
                                                  c = str[16];
                                                  if (!c) return NEW_SRV_ACTION_PRIV_SUBMIT_PAGE;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          } else if (c < 'p') {
                                            if (c == 'c') {
                                              c = str[13];
                                              if (c == 'l') {
                                                c = str[14];
                                                if (c == 'a') {
                                                  c = str[15];
                                                  if (c == 'r') {
                                                    c = str[16];
                                                    if (!c) return NEW_SRV_ACTION_PRIV_SUBMIT_CLAR;
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                          } else {
                                            if (c == 'r') {
                                              c = str[13];
                                              if (c == 'u') {
                                                c = str[14];
                                                if (c == 'n') {
                                                  c = str[15];
                                                  if (c == '-') {
                                                    c = str[16];
                                                    if (c == 'j') {
                                                      c = str[17];
                                                      if (c == 'u') {
                                                        c = str[18];
                                                        if (c == 's') {
                                                          c = str[19];
                                                          if (c == 't') {
                                                            c = str[20];
                                                            if (c == '-') {
                                                              c = str[21];
                                                              if (c == 'o') {
                                                                c = str[22];
                                                                if (c == 'k') {
                                                                  c = str[23];
                                                                  if (!c) return NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_OK;
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              } else if (c < 'o') {
                                                                if (c == 'i') {
                                                                  c = str[22];
                                                                  if (c == 'g') {
                                                                    c = str[23];
                                                                    if (c == 'n') {
                                                                      c = str[24];
                                                                      if (c == 'o') {
                                                                        c = str[25];
                                                                        if (c == 'r') {
                                                                          c = str[26];
                                                                          if (c == 'e') {
                                                                            c = str[27];
                                                                            if (!c) return NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_IGNORE;
                                                                            return 0;
                                                                          }
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                              } else {
                                                                if (c == 's') {
                                                                  c = str[22];
                                                                  if (c == 'u') {
                                                                    c = str[23];
                                                                    if (c == 'm') {
                                                                      c = str[24];
                                                                      if (c == 'm') {
                                                                        c = str[25];
                                                                        if (c == 'o') {
                                                                          c = str[26];
                                                                          if (c == 'n') {
                                                                            c = str[27];
                                                                            if (!c) return NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_SUMMON;
                                                                            return 0;
                                                                          }
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    } else if (c < 'j') {
                                                      if (c == 'c') {
                                                        c = str[17];
                                                        if (c == 'o') {
                                                          c = str[18];
                                                          if (c == 'm') {
                                                            c = str[19];
                                                            if (c == 'm') {
                                                              c = str[20];
                                                              if (c == 'e') {
                                                                c = str[21];
                                                                if (c == 'n') {
                                                                  c = str[22];
                                                                  if (c == 't') {
                                                                    c = str[23];
                                                                    if (!c) return NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT;
                                                                    if (c == '-') {
                                                                      c = str[24];
                                                                      if (c == 'a') {
                                                                        c = str[25];
                                                                        if (c == 'n') {
                                                                          c = str[26];
                                                                          if (c == 'd') {
                                                                            c = str[27];
                                                                            if (c == '-') {
                                                                              c = str[28];
                                                                              if (c == 'r') {
                                                                                c = str[29];
                                                                                if (c == 'e') {
                                                                                  c = str[30];
                                                                                  if (c == 'j') {
                                                                                    c = str[31];
                                                                                    if (c == 'e') {
                                                                                      c = str[32];
                                                                                      if (c == 'c') {
                                                                                        c = str[33];
                                                                                        if (c == 't') {
                                                                                          c = str[34];
                                                                                          if (!c) return NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_REJECT;
                                                                                          return 0;
                                                                                        }
                                                                                        return 0;
                                                                                      }
                                                                                      return 0;
                                                                                    }
                                                                                    return 0;
                                                                                  }
                                                                                  return 0;
                                                                                }
                                                                                return 0;
                                                                              } else if (c < 'r') {
                                                                                if (c == 'o') {
                                                                                  c = str[29];
                                                                                  if (c == 'k') {
                                                                                    c = str[30];
                                                                                    if (!c) return NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_OK;
                                                                                    return 0;
                                                                                  }
                                                                                  return 0;
                                                                                } else if (c < 'o') {
                                                                                  if (c == 'i') {
                                                                                    c = str[29];
                                                                                    if (c == 'g') {
                                                                                      c = str[30];
                                                                                      if (c == 'n') {
                                                                                        c = str[31];
                                                                                        if (c == 'o') {
                                                                                          c = str[32];
                                                                                          if (c == 'r') {
                                                                                            c = str[33];
                                                                                            if (c == 'e') {
                                                                                              c = str[34];
                                                                                              if (!c) return NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_IGNORE;
                                                                                              return 0;
                                                                                            }
                                                                                            return 0;
                                                                                          }
                                                                                          return 0;
                                                                                        }
                                                                                        return 0;
                                                                                      }
                                                                                      return 0;
                                                                                    }
                                                                                    return 0;
                                                                                  }
                                                                                } else {
                                                                                }
                                                                              } else {
                                                                                if (c == 's') {
                                                                                  c = str[29];
                                                                                  if (c == 'u') {
                                                                                    c = str[30];
                                                                                    if (c == 'm') {
                                                                                      c = str[31];
                                                                                      if (c == 'm') {
                                                                                        c = str[32];
                                                                                        if (c == 'o') {
                                                                                          c = str[33];
                                                                                          if (c == 'n') {
                                                                                            c = str[34];
                                                                                            if (!c) return NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_SUMMON;
                                                                                            return 0;
                                                                                          }
                                                                                          return 0;
                                                                                        }
                                                                                        return 0;
                                                                                      }
                                                                                      return 0;
                                                                                    }
                                                                                    return 0;
                                                                                  }
                                                                                  return 0;
                                                                                }
                                                                              }
                                                                              return 0;
                                                                            }
                                                                            return 0;
                                                                          }
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                    } else {
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          } else {
                          }
                        }
                        return 0;
                      }
                      return 0;
                    }
                  }
                  return 0;
                }
              } else {
              }
              return 0;
            } else if (c < 'r') {
              if (c == 'i') {
                c = str[2];
                if (c == 'n') {
                  c = str[3];
                  if (c == 'g') {
                    c = str[4];
                    if (!c) return NEW_SRV_ACTION_PING;
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
            } else {
            }
            return 0;
          }
        } else {
        }
      }
    } else {
      if (c == 'v') {
        c = str[1];
        if (c == 'i') {
          c = str[2];
          if (c == 'r') {
            c = str[3];
            if (c == 't') {
              c = str[4];
              if (c == 'u') {
                c = str[5];
                if (c == 'a') {
                  c = str[6];
                  if (c == 'l') {
                    c = str[7];
                    if (c == '-') {
                      c = str[8];
                      if (c == 's') {
                        c = str[9];
                        if (c == 't') {
                          c = str[10];
                          if (c == 'o') {
                            c = str[11];
                            if (c == 'p') {
                              c = str[12];
                              if (!c) return NEW_SRV_ACTION_VIRTUAL_STOP;
                              return 0;
                            }
                            return 0;
                          } else if (c < 'o') {
                            if (c == 'a') {
                              c = str[11];
                              if (c == 'r') {
                                c = str[12];
                                if (c == 't') {
                                  c = str[13];
                                  if (!c) return NEW_SRV_ACTION_VIRTUAL_START;
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          } else {
                          }
                          return 0;
                        }
                        return 0;
                      } else if (c < 's') {
                        if (c == 'r') {
                          c = str[9];
                          if (c == 'e') {
                            c = str[10];
                            if (c == 's') {
                              c = str[11];
                              if (c == 't') {
                                c = str[12];
                                if (c == 'a') {
                                  c = str[13];
                                  if (c == 'r') {
                                    c = str[14];
                                    if (c == 't') {
                                      c = str[15];
                                      if (!c) return NEW_SRV_ACTION_VIRTUAL_RESTART;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                      } else {
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          } else if (c < 'r') {
            if (c == 'e') {
              c = str[3];
              if (c == 'w') {
                c = str[4];
                if (c == '-') {
                  c = str[5];
                  if (c == 'p') {
                    c = str[6];
                    if (c == 'r') {
                      c = str[7];
                      if (c == 'o') {
                        c = str[8];
                        if (c == 'b') {
                          c = str[9];
                          if (c == 'l') {
                            c = str[10];
                            if (c == 'e') {
                              c = str[11];
                              if (c == 'm') {
                                c = str[12];
                                if (c == '-') {
                                  c = str[13];
                                  if (c == 's') {
                                    c = str[14];
                                    if (c == 'u') {
                                      c = str[15];
                                      if (c == 'm') {
                                        c = str[16];
                                        if (c == 'm') {
                                          c = str[17];
                                          if (c == 'a') {
                                            c = str[18];
                                            if (c == 'r') {
                                              c = str[19];
                                              if (c == 'y') {
                                                c = str[20];
                                                if (!c) return NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      } else if (c < 'm') {
                                        if (c == 'b') {
                                          c = str[16];
                                          if (c == 'm') {
                                            c = str[17];
                                            if (c == 'i') {
                                              c = str[18];
                                              if (c == 't') {
                                                c = str[19];
                                                if (!c) return NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                      } else {
                                      }
                                      return 0;
                                    } else if (c < 'u') {
                                      if (c == 't') {
                                        c = str[15];
                                        if (c == 'a') {
                                          c = str[16];
                                          if (c == 't') {
                                            c = str[17];
                                            if (c == 'e') {
                                              c = str[18];
                                              if (c == 'm') {
                                                c = str[19];
                                                if (c == 'e') {
                                                  c = str[20];
                                                  if (c == 'n') {
                                                    c = str[21];
                                                    if (c == 't') {
                                                      c = str[22];
                                                      if (c == 's') {
                                                        c = str[23];
                                                        if (!c) return NEW_SRV_ACTION_VIEW_PROBLEM_STATEMENTS;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                    } else {
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  } else if (c < 'p') {
                    if (c == 'e') {
                      c = str[6];
                      if (c == 'x') {
                        c = str[7];
                        if (c == 'a') {
                          c = str[8];
                          if (c == 'm') {
                            c = str[9];
                            if (c == '-') {
                              c = str[10];
                              if (c == 'i') {
                                c = str[11];
                                if (c == 'n') {
                                  c = str[12];
                                  if (c == 'f') {
                                    c = str[13];
                                    if (c == 'o') {
                                      c = str[14];
                                      if (!c) return NEW_SRV_ACTION_VIEW_EXAM_INFO;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    } else if (c < 'e') {
                      if (c == 'c') {
                        c = str[6];
                        if (c == 'n') {
                          c = str[7];
                          if (c == 't') {
                            c = str[8];
                            if (c == 's') {
                              c = str[9];
                              if (c == '-') {
                                c = str[10];
                                if (c == 'p') {
                                  c = str[11];
                                  if (c == 'w') {
                                    c = str[12];
                                    if (c == 'd') {
                                      c = str[13];
                                      if (c == 's') {
                                        c = str[14];
                                        if (!c) return NEW_SRV_ACTION_VIEW_CNTS_PWDS;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 'n') {
                          if (c == 'l') {
                            c = str[7];
                            if (c == 'a') {
                              c = str[8];
                              if (c == 'r') {
                                c = str[9];
                                if (!c) return NEW_SRV_ACTION_VIEW_CLAR;
                                if (c == 's') {
                                  c = str[10];
                                  if (!c) return NEW_SRV_ACTION_VIEW_CLARS;
                                  return 0;
                                } else if (c < 's') {
                                  if (c == '-') {
                                    c = str[10];
                                    if (c == 's') {
                                      c = str[11];
                                      if (c == 'u') {
                                        c = str[12];
                                        if (c == 'b') {
                                          c = str[13];
                                          if (c == 'm') {
                                            c = str[14];
                                            if (c == 'i') {
                                              c = str[15];
                                              if (c == 't') {
                                                c = str[16];
                                                if (!c) return NEW_SRV_ACTION_VIEW_CLAR_SUBMIT;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                } else {
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                        } else {
                        }
                        return 0;
                      } else if (c < 'c') {
                        if (c == 'a') {
                          c = str[6];
                          if (c == 'u') {
                            c = str[7];
                            if (c == 'd') {
                              c = str[8];
                              if (c == 'i') {
                                c = str[9];
                                if (c == 't') {
                                  c = str[10];
                                  if (c == '-') {
                                    c = str[11];
                                    if (c == 'l') {
                                      c = str[12];
                                      if (c == 'o') {
                                        c = str[13];
                                        if (c == 'g') {
                                          c = str[14];
                                          if (!c) return NEW_SRV_ACTION_VIEW_AUDIT_LOG;
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                      } else {
                      }
                    } else {
                      if (c == 'o') {
                        c = str[6];
                        if (c == 'n') {
                          c = str[7];
                          if (c == 'l') {
                            c = str[8];
                            if (c == 'i') {
                              c = str[9];
                              if (c == 'n') {
                                c = str[10];
                                if (c == 'e') {
                                  c = str[11];
                                  if (c == '-') {
                                    c = str[12];
                                    if (c == 'u') {
                                      c = str[13];
                                      if (c == 's') {
                                        c = str[14];
                                        if (c == 'e') {
                                          c = str[15];
                                          if (c == 'r') {
                                            c = str[16];
                                            if (c == 's') {
                                              c = str[17];
                                              if (!c) return NEW_SRV_ACTION_VIEW_ONLINE_USERS;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      } else if (c < 'o') {
                        if (c == 'i') {
                          c = str[6];
                          if (c == 'p') {
                            c = str[7];
                            if (c == '-') {
                              c = str[8];
                              if (c == 'u') {
                                c = str[9];
                                if (c == 's') {
                                  c = str[10];
                                  if (c == 'e') {
                                    c = str[11];
                                    if (c == 'r') {
                                      c = str[12];
                                      if (c == 's') {
                                        c = str[13];
                                        if (!c) return NEW_SRV_ACTION_VIEW_IP_USERS;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                      } else {
                      }
                    }
                  } else {
                    if (c == 't') {
                      c = str[6];
                      if (c == 'e') {
                        c = str[7];
                        if (c == 's') {
                          c = str[8];
                          if (c == 't') {
                            c = str[9];
                            if (c == 'i') {
                              c = str[10];
                              if (c == 'n') {
                                c = str[11];
                                if (c == 'g') {
                                  c = str[12];
                                  if (c == '-') {
                                    c = str[13];
                                    if (c == 'q') {
                                      c = str[14];
                                      if (c == 'u') {
                                        c = str[15];
                                        if (c == 'e') {
                                          c = str[16];
                                          if (c == 'u') {
                                            c = str[17];
                                            if (c == 'e') {
                                              c = str[18];
                                              if (!c) return NEW_SRV_ACTION_VIEW_TESTING_QUEUE;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            } else if (c < 'i') {
                              if (c == '-') {
                                c = str[10];
                                if (c == 'e') {
                                  c = str[11];
                                  if (c == 'r') {
                                    c = str[12];
                                    if (c == 'r') {
                                      c = str[13];
                                      if (c == 'o') {
                                        c = str[14];
                                        if (c == 'r') {
                                          c = str[15];
                                          if (!c) return NEW_SRV_ACTION_VIEW_TEST_ERROR;
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                } else if (c < 'e') {
                                  if (c == 'c') {
                                    c = str[11];
                                    if (c == 'h') {
                                      c = str[12];
                                      if (c == 'e') {
                                        c = str[13];
                                        if (c == 'c') {
                                          c = str[14];
                                          if (c == 'k') {
                                            c = str[15];
                                            if (c == 'e') {
                                              c = str[16];
                                              if (c == 'r') {
                                                c = str[17];
                                                if (!c) return NEW_SRV_ACTION_VIEW_TEST_CHECKER;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  } else if (c < 'c') {
                                    if (c == 'a') {
                                      c = str[11];
                                      if (c == 'n') {
                                        c = str[12];
                                        if (c == 's') {
                                          c = str[13];
                                          if (c == 'w') {
                                            c = str[14];
                                            if (c == 'e') {
                                              c = str[15];
                                              if (c == 'r') {
                                                c = str[16];
                                                if (!c) return NEW_SRV_ACTION_VIEW_TEST_ANSWER;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                  } else {
                                  }
                                } else {
                                  if (c == 'o') {
                                    c = str[11];
                                    if (c == 'u') {
                                      c = str[12];
                                      if (c == 't') {
                                        c = str[13];
                                        if (c == 'p') {
                                          c = str[14];
                                          if (c == 'u') {
                                            c = str[15];
                                            if (c == 't') {
                                              c = str[16];
                                              if (!c) return NEW_SRV_ACTION_VIEW_TEST_OUTPUT;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  } else if (c < 'o') {
                                    if (c == 'i') {
                                      c = str[11];
                                      if (c == 'n') {
                                        c = str[12];
                                        if (c == 'p') {
                                          c = str[13];
                                          if (c == 'u') {
                                            c = str[14];
                                            if (c == 't') {
                                              c = str[15];
                                              if (!c) return NEW_SRV_ACTION_VIEW_TEST_INPUT;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        } else if (c < 'p') {
                                          if (c == 'f') {
                                            c = str[13];
                                            if (c == 'o') {
                                              c = str[14];
                                              if (!c) return NEW_SRV_ACTION_VIEW_TEST_INFO;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                        } else {
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                  } else {
                                  }
                                }
                                return 0;
                              }
                            } else {
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    } else if (c < 't') {
                      if (c == 's') {
                        c = str[6];
                        if (c == 't') {
                          c = str[7];
                          if (c == 'a') {
                            c = str[8];
                            if (c == 'r') {
                              c = str[9];
                              if (c == 't') {
                                c = str[10];
                                if (c == 's') {
                                  c = str[11];
                                  if (c == 't') {
                                    c = str[12];
                                    if (c == 'o') {
                                      c = str[13];
                                      if (c == 'p') {
                                        c = str[14];
                                        if (!c) return NEW_SRV_ACTION_VIEW_STARTSTOP;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 't') {
                          if (c == 'o') {
                            c = str[7];
                            if (c == 'u') {
                              c = str[8];
                              if (c == 'r') {
                                c = str[9];
                                if (c == 'c') {
                                  c = str[10];
                                  if (c == 'e') {
                                    c = str[11];
                                    if (!c) return NEW_SRV_ACTION_VIEW_SOURCE;
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 'o') {
                            if (c == 'e') {
                              c = str[7];
                              if (c == 't') {
                                c = str[8];
                                if (c == 't') {
                                  c = str[9];
                                  if (c == 'i') {
                                    c = str[10];
                                    if (c == 'n') {
                                      c = str[11];
                                      if (c == 'g') {
                                        c = str[12];
                                        if (c == 's') {
                                          c = str[13];
                                          if (!c) return NEW_SRV_ACTION_VIEW_SETTINGS;
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          } else {
                          }
                        } else {
                          if (c == 'u') {
                            c = str[7];
                            if (c == 'b') {
                              c = str[8];
                              if (c == 'm') {
                                c = str[9];
                                if (c == 'i') {
                                  c = str[10];
                                  if (c == 's') {
                                    c = str[11];
                                    if (c == 's') {
                                      c = str[12];
                                      if (c == 'i') {
                                        c = str[13];
                                        if (c == 'o') {
                                          c = str[14];
                                          if (c == 'n') {
                                            c = str[15];
                                            if (c == 's') {
                                              c = str[16];
                                              if (!c) return NEW_SRV_ACTION_VIEW_SUBMISSIONS;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                        }
                        return 0;
                      } else if (c < 's') {
                        if (c == 'r') {
                          c = str[6];
                          if (c == 'u') {
                            c = str[7];
                            if (c == 'n') {
                              c = str[8];
                              if (c == 's') {
                                c = str[9];
                                if (c == '-') {
                                  c = str[10];
                                  if (c == 'd') {
                                    c = str[11];
                                    if (c == 'u') {
                                      c = str[12];
                                      if (c == 'm') {
                                        c = str[13];
                                        if (c == 'p') {
                                          c = str[14];
                                          if (!c) return NEW_SRV_ACTION_VIEW_RUNS_DUMP;
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 'u') {
                            if (c == 'e') {
                              c = str[7];
                              if (c == 'p') {
                                c = str[8];
                                if (c == 'o') {
                                  c = str[9];
                                  if (c == 'r') {
                                    c = str[10];
                                    if (c == 't') {
                                      c = str[11];
                                      if (!c) return NEW_SRV_ACTION_VIEW_REPORT;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              } else if (c < 'p') {
                                if (c == 'g') {
                                  c = str[8];
                                  if (c == '-') {
                                    c = str[9];
                                    if (c == 'p') {
                                      c = str[10];
                                      if (c == 'w') {
                                        c = str[11];
                                        if (c == 'd') {
                                          c = str[12];
                                          if (c == 's') {
                                            c = str[13];
                                            if (!c) return NEW_SRV_ACTION_VIEW_REG_PWDS;
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                              } else {
                              }
                              return 0;
                            }
                          } else {
                          }
                          return 0;
                        }
                      } else {
                      }
                    } else {
                      if (c == 'u') {
                        c = str[6];
                        if (c == 's') {
                          c = str[7];
                          if (c == 'e') {
                            c = str[8];
                            if (c == 'r') {
                              c = str[9];
                              if (c == 's') {
                                c = str[10];
                                if (!c) return NEW_SRV_ACTION_VIEW_USERS;
                                if (c == '-') {
                                  c = str[11];
                                  if (c == 'n') {
                                    c = str[12];
                                    if (c == 'e') {
                                      c = str[13];
                                      if (c == 'w') {
                                        c = str[14];
                                        if (c == '-') {
                                          c = str[15];
                                          if (c == 'p') {
                                            c = str[16];
                                            if (c == 'a') {
                                              c = str[17];
                                              if (c == 'g') {
                                                c = str[18];
                                                if (c == 'e') {
                                                  c = str[19];
                                                  if (!c) return NEW_SRV_ACTION_VIEW_USERS_NEW_PAGE;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          } else if (c < 'p') {
                                            if (c == 'a') {
                                              c = str[16];
                                              if (c == 'j') {
                                                c = str[17];
                                                if (c == 'a') {
                                                  c = str[18];
                                                  if (c == 'x') {
                                                    c = str[19];
                                                    if (!c) return NEW_SRV_ACTION_VIEW_USERS_NEW_AJAX;
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                          } else {
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              } else if (c < 's') {
                                if (c == '-') {
                                  c = str[10];
                                  if (c == 'i') {
                                    c = str[11];
                                    if (c == 'p') {
                                      c = str[12];
                                      if (c == 's') {
                                        c = str[13];
                                        if (!c) return NEW_SRV_ACTION_VIEW_USER_IPS;
                                        return 0;
                                      }
                                      return 0;
                                    } else if (c < 'p') {
                                      if (c == 'n') {
                                        c = str[12];
                                        if (c == 'f') {
                                          c = str[13];
                                          if (c == 'o') {
                                            c = str[14];
                                            if (!c) return NEW_SRV_ACTION_VIEW_USER_INFO;
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                    } else {
                                    }
                                    return 0;
                                  } else if (c < 'i') {
                                    if (c == 'd') {
                                      c = str[11];
                                      if (c == 'u') {
                                        c = str[12];
                                        if (c == 'm') {
                                          c = str[13];
                                          if (c == 'p') {
                                            c = str[14];
                                            if (!c) return NEW_SRV_ACTION_VIEW_USER_DUMP;
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                  } else {
                                    if (c == 'r') {
                                      c = str[11];
                                      if (c == 'e') {
                                        c = str[12];
                                        if (c == 'p') {
                                          c = str[13];
                                          if (c == 'o') {
                                            c = str[14];
                                            if (c == 'r') {
                                              c = str[15];
                                              if (c == 't') {
                                                c = str[16];
                                                if (!c) return NEW_SRV_ACTION_VIEW_USER_REPORT;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                  }
                                  return 0;
                                }
                              } else {
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                    }
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
          } else {
          }
          return 0;
        } else if (c < 'i') {
          if (c == 'c') {
            c = str[2];
            if (c == 's') {
              c = str[3];
              if (c == '-') {
                c = str[4];
                if (c == 'w') {
                  c = str[5];
                  if (c == 'e') {
                    c = str[6];
                    if (c == 'b') {
                      c = str[7];
                      if (c == 'h') {
                        c = str[8];
                        if (c == 'o') {
                          c = str[9];
                          if (c == 'o') {
                            c = str[10];
                            if (c == 'k') {
                              c = str[11];
                              if (!c) return NEW_SRV_ACTION_VCS_WEBHOOK;
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
        } else {
        }
        return 0;
      } else if (c < 'v') {
        if (c == 'u') {
          c = str[1];
          if (c == 'p') {
            c = str[2];
            if (c == 'l') {
              c = str[3];
              if (c == 'o') {
                c = str[4];
                if (c == 'a') {
                  c = str[5];
                  if (c == 'd') {
                    c = str[6];
                    if (c == '-') {
                      c = str[7];
                      if (c == 'r') {
                        c = str[8];
                        if (c == 'u') {
                          c = str[9];
                          if (c == 'n') {
                            c = str[10];
                            if (c == 'l') {
                              c = str[11];
                              if (c == 'o') {
                                c = str[12];
                                if (c == 'g') {
                                  c = str[13];
                                  if (c == '-') {
                                    c = str[14];
                                    if (c == 'x') {
                                      c = str[15];
                                      if (c == 'm') {
                                        c = str[16];
                                        if (c == 'l') {
                                          c = str[17];
                                          if (c == '-') {
                                            c = str[18];
                                            if (c == '2') {
                                              c = str[19];
                                              if (!c) return NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_2;
                                              return 0;
                                            } else if (c < '2') {
                                              if (c == '1') {
                                                c = str[19];
                                                if (!c) return NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_1;
                                                return 0;
                                              }
                                            } else {
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    } else if (c < 'x') {
                                      if (c == 'c') {
                                        c = str[15];
                                        if (c == 's') {
                                          c = str[16];
                                          if (c == 'v') {
                                            c = str[17];
                                            if (c == '-') {
                                              c = str[18];
                                              if (c == '2') {
                                                c = str[19];
                                                if (!c) return NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_2;
                                                return 0;
                                              } else if (c < '2') {
                                                if (c == '1') {
                                                  c = str[19];
                                                  if (!c) return NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_1;
                                                  return 0;
                                                }
                                              } else {
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                    } else {
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 'u') {
                          if (c == 'e') {
                            c = str[9];
                            if (c == 'p') {
                              c = str[10];
                              if (c == 'o') {
                                c = str[11];
                                if (c == 'r') {
                                  c = str[12];
                                  if (c == 't') {
                                    c = str[13];
                                    if (!c) return NEW_SRV_ACTION_UPLOAD_REPORT;
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                        } else {
                        }
                        return 0;
                      } else if (c < 'r') {
                        if (c == 'a') {
                          c = str[8];
                          if (c == 'v') {
                            c = str[9];
                            if (c == 'a') {
                              c = str[10];
                              if (c == 't') {
                                c = str[11];
                                if (c == 'a') {
                                  c = str[12];
                                  if (c == 'r') {
                                    c = str[13];
                                    if (!c) return NEW_SRV_ACTION_UPLOAD_AVATAR;
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                      } else {
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            } else if (c < 'l') {
              if (c == 'd') {
                c = str[3];
                if (c == 'a') {
                  c = str[4];
                  if (c == 't') {
                    c = str[5];
                    if (c == 'e') {
                      c = str[6];
                      if (c == '-') {
                        c = str[7];
                        if (c == 's') {
                          c = str[8];
                          if (c == 't') {
                            c = str[9];
                            if (c == 'a') {
                              c = str[10];
                              if (c == 'n') {
                                c = str[11];
                                if (c == 'd') {
                                  c = str[12];
                                  if (c == 'i') {
                                    c = str[13];
                                    if (c == 'n') {
                                      c = str[14];
                                      if (c == 'g') {
                                        c = str[15];
                                        if (c == 's') {
                                          c = str[16];
                                          if (c == '-') {
                                            c = str[17];
                                            if (c == '2') {
                                              c = str[18];
                                              if (!c) return NEW_SRV_ACTION_UPDATE_STANDINGS_2;
                                              return 0;
                                            } else if (c < '2') {
                                              if (c == '1') {
                                                c = str[18];
                                                if (!c) return NEW_SRV_ACTION_UPDATE_STANDINGS_1;
                                                return 0;
                                              }
                                            } else {
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 's') {
                          if (c == 'a') {
                            c = str[8];
                            if (c == 'n') {
                              c = str[9];
                              if (c == 's') {
                                c = str[10];
                                if (c == 'w') {
                                  c = str[11];
                                  if (c == 'e') {
                                    c = str[12];
                                    if (c == 'r') {
                                      c = str[13];
                                      if (!c) return NEW_SRV_ACTION_UPDATE_ANSWER;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                        } else {
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
            } else {
              if (c == 's') {
                c = str[3];
                if (c == 'o') {
                  c = str[4];
                  if (c == 'l') {
                    c = str[5];
                    if (c == 'v') {
                      c = str[6];
                      if (c == 'i') {
                        c = str[7];
                        if (c == 'n') {
                          c = str[8];
                          if (c == 'g') {
                            c = str[9];
                            if (c == '-') {
                              c = str[10];
                              if (c == 'c') {
                                c = str[11];
                                if (c == 'o') {
                                  c = str[12];
                                  if (c == 'n') {
                                    c = str[13];
                                    if (c == 'f') {
                                      c = str[14];
                                      if (c == 'i') {
                                        c = str[15];
                                        if (c == 'g') {
                                          c = str[16];
                                          if (c == '-') {
                                            c = str[17];
                                            if (c == '3') {
                                              c = str[18];
                                              if (!c) return NEW_SRV_ACTION_UPSOLVING_CONFIG_3;
                                              return 0;
                                            } else if (c < '3') {
                                              if (c == '2') {
                                                c = str[18];
                                                if (!c) return NEW_SRV_ACTION_UPSOLVING_CONFIG_2;
                                                return 0;
                                              } else if (c < '2') {
                                                if (c == '1') {
                                                  c = str[18];
                                                  if (!c) return NEW_SRV_ACTION_UPSOLVING_CONFIG_1;
                                                  return 0;
                                                }
                                              } else {
                                              }
                                            } else {
                                              if (c == '4') {
                                                c = str[18];
                                                if (!c) return NEW_SRV_ACTION_UPSOLVING_CONFIG_4;
                                                return 0;
                                              }
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
            }
            return 0;
          } else if (c < 'p') {
            if (c == 'n') {
              c = str[2];
              if (c == 'm') {
                c = str[3];
                if (c == 'a') {
                  c = str[4];
                  if (c == 'r') {
                    c = str[5];
                    if (c == 'k') {
                      c = str[6];
                      if (c == '-') {
                        c = str[7];
                        if (c == 'd') {
                          c = str[8];
                          if (c == 'i') {
                            c = str[9];
                            if (c == 's') {
                              c = str[10];
                              if (c == 'p') {
                                c = str[11];
                                if (c == 'l') {
                                  c = str[12];
                                  if (c == 'a') {
                                    c = str[13];
                                    if (c == 'y') {
                                      c = str[14];
                                      if (c == 'e') {
                                        c = str[15];
                                        if (c == 'd') {
                                          c = str[16];
                                          if (c == '-') {
                                            c = str[17];
                                            if (c == '2') {
                                              c = str[18];
                                              if (!c) return NEW_SRV_ACTION_UNMARK_DISPLAYED_2;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              } else if (c < 'm') {
                if (c == 'a') {
                  c = str[3];
                  if (c == 's') {
                    c = str[4];
                    if (c == 's') {
                      c = str[5];
                      if (c == 'i') {
                        c = str[6];
                        if (c == 'g') {
                          c = str[7];
                          if (c == 'n') {
                            c = str[8];
                            if (c == '-') {
                              c = str[9];
                              if (c == 'e') {
                                c = str[10];
                                if (c == 'x') {
                                  c = str[11];
                                  if (c == 'a') {
                                    c = str[12];
                                    if (c == 'm') {
                                      c = str[13];
                                      if (c == 'i') {
                                        c = str[14];
                                        if (c == 'n') {
                                          c = str[15];
                                          if (c == 'e') {
                                            c = str[16];
                                            if (c == 'r') {
                                              c = str[17];
                                              if (!c) return NEW_SRV_ACTION_UNASSIGN_EXAMINER;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
              } else {
              }
              return 0;
            }
          } else {
            if (c == 's') {
              c = str[2];
              if (c == 'e') {
                c = str[3];
                if (c == 'r') {
                  c = str[4];
                  if (c == 's') {
                    c = str[5];
                    if (c == '-') {
                      c = str[6];
                      if (c == 'r') {
                        c = str[7];
                        if (c == 'e') {
                          c = str[8];
                          if (c == 'm') {
                            c = str[9];
                            if (c == 'o') {
                              c = str[10];
                              if (c == 'v') {
                                c = str[11];
                                if (c == 'e') {
                                  c = str[12];
                                  if (c == '-') {
                                    c = str[13];
                                    if (c == 'r') {
                                      c = str[14];
                                      if (c == 'e') {
                                        c = str[15];
                                        if (c == 'g') {
                                          c = str[16];
                                          if (c == 'i') {
                                            c = str[17];
                                            if (c == 's') {
                                              c = str[18];
                                              if (c == 't') {
                                                c = str[19];
                                                if (c == 'r') {
                                                  c = str[20];
                                                  if (c == 'a') {
                                                    c = str[21];
                                                    if (c == 't') {
                                                      c = str[22];
                                                      if (c == 'i') {
                                                        c = str[23];
                                                        if (c == 'o') {
                                                          c = str[24];
                                                          if (c == 'n') {
                                                            c = str[25];
                                                            if (c == 's') {
                                                              c = str[26];
                                                              if (!c) return NEW_SRV_ACTION_USERS_REMOVE_REGISTRATIONS;
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      } else if (c < 'r') {
                        if (c == 'c') {
                          c = str[7];
                          if (c == 'l') {
                            c = str[8];
                            if (c == 'e') {
                              c = str[9];
                              if (c == 'a') {
                                c = str[10];
                                if (c == 'r') {
                                  c = str[11];
                                  if (c == '-') {
                                    c = str[12];
                                    if (c == 'i') {
                                      c = str[13];
                                      if (c == 'n') {
                                        c = str[14];
                                        if (c == 'v') {
                                          c = str[15];
                                          if (c == 'i') {
                                            c = str[16];
                                            if (c == 's') {
                                              c = str[17];
                                              if (c == 'i') {
                                                c = str[18];
                                                if (c == 'b') {
                                                  c = str[19];
                                                  if (c == 'l') {
                                                    c = str[20];
                                                    if (c == 'e') {
                                                      c = str[21];
                                                      if (!c) return NEW_SRV_ACTION_USERS_CLEAR_INVISIBLE;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        } else if (c < 'v') {
                                          if (c == 'c') {
                                            c = str[15];
                                            if (c == 'o') {
                                              c = str[16];
                                              if (c == 'm') {
                                                c = str[17];
                                                if (c == 'p') {
                                                  c = str[18];
                                                  if (c == 'l') {
                                                    c = str[19];
                                                    if (c == 'e') {
                                                      c = str[20];
                                                      if (c == 't') {
                                                        c = str[21];
                                                        if (c == 'e') {
                                                          c = str[22];
                                                          if (!c) return NEW_SRV_ACTION_USERS_CLEAR_INCOMPLETE;
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                        } else {
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    } else if (c < 'i') {
                                      if (c == 'd') {
                                        c = str[13];
                                        if (c == 'i') {
                                          c = str[14];
                                          if (c == 's') {
                                            c = str[15];
                                            if (c == 'q') {
                                              c = str[16];
                                              if (c == 'u') {
                                                c = str[17];
                                                if (c == 'a') {
                                                  c = str[18];
                                                  if (c == 'l') {
                                                    c = str[19];
                                                    if (c == 'i') {
                                                      c = str[20];
                                                      if (c == 'f') {
                                                        c = str[21];
                                                        if (c == 'i') {
                                                          c = str[22];
                                                          if (c == 'e') {
                                                            c = str[23];
                                                            if (c == 'd') {
                                                              c = str[24];
                                                              if (!c) return NEW_SRV_ACTION_USERS_CLEAR_DISQUALIFIED;
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      } else if (c < 'd') {
                                        if (c == 'b') {
                                          c = str[13];
                                          if (c == 'a') {
                                            c = str[14];
                                            if (c == 'n') {
                                              c = str[15];
                                              if (c == 'n') {
                                                c = str[16];
                                                if (c == 'e') {
                                                  c = str[17];
                                                  if (c == 'd') {
                                                    c = str[18];
                                                    if (!c) return NEW_SRV_ACTION_USERS_CLEAR_BANNED;
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                      } else {
                                      }
                                    } else {
                                      if (c == 'l') {
                                        c = str[13];
                                        if (c == 'o') {
                                          c = str[14];
                                          if (c == 'c') {
                                            c = str[15];
                                            if (c == 'k') {
                                              c = str[16];
                                              if (c == 'e') {
                                                c = str[17];
                                                if (c == 'd') {
                                                  c = str[18];
                                                  if (!c) return NEW_SRV_ACTION_USERS_CLEAR_LOCKED;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 'l') {
                            if (c == 'h') {
                              c = str[8];
                              if (c == 'a') {
                                c = str[9];
                                if (c == 'n') {
                                  c = str[10];
                                  if (c == 'g') {
                                    c = str[11];
                                    if (c == 'e') {
                                      c = str[12];
                                      if (c == '-') {
                                        c = str[13];
                                        if (c == 'f') {
                                          c = str[14];
                                          if (c == 'l') {
                                            c = str[15];
                                            if (c == 'a') {
                                              c = str[16];
                                              if (c == 'g') {
                                                c = str[17];
                                                if (c == 's') {
                                                  c = str[18];
                                                  if (!c) return NEW_SRV_ACTION_USERS_CHANGE_FLAGS;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          } else {
                          }
                          return 0;
                        } else if (c < 'c') {
                          if (c == 'a') {
                            c = str[7];
                            if (c == 'd') {
                              c = str[8];
                              if (c == 'd') {
                                c = str[9];
                                if (c == '-') {
                                  c = str[10];
                                  if (c == 'b') {
                                    c = str[11];
                                    if (c == 'y') {
                                      c = str[12];
                                      if (c == '-') {
                                        c = str[13];
                                        if (c == 'u') {
                                          c = str[14];
                                          if (c == 's') {
                                            c = str[15];
                                            if (c == 'e') {
                                              c = str[16];
                                              if (c == 'r') {
                                                c = str[17];
                                                if (c == '-') {
                                                  c = str[18];
                                                  if (c == 'i') {
                                                    c = str[19];
                                                    if (c == 'd') {
                                                      c = str[20];
                                                      if (!c) return NEW_SRV_ACTION_USERS_ADD_BY_USER_ID;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        } else if (c < 'u') {
                                          if (c == 'l') {
                                            c = str[14];
                                            if (c == 'o') {
                                              c = str[15];
                                              if (c == 'g') {
                                                c = str[16];
                                                if (c == 'i') {
                                                  c = str[17];
                                                  if (c == 'n') {
                                                    c = str[18];
                                                    if (!c) return NEW_SRV_ACTION_USERS_ADD_BY_LOGIN;
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                        } else {
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                        } else {
                        }
                      } else {
                        if (c == 's') {
                          c = str[7];
                          if (c == 'e') {
                            c = str[8];
                            if (c == 't') {
                              c = str[9];
                              if (c == '-') {
                                c = str[10];
                                if (c == 'o') {
                                  c = str[11];
                                  if (c == 'k') {
                                    c = str[12];
                                    if (!c) return NEW_SRV_ACTION_USERS_SET_OK;
                                    return 0;
                                  }
                                  return 0;
                                } else if (c < 'o') {
                                  if (c == 'i') {
                                    c = str[11];
                                    if (c == 'n') {
                                      c = str[12];
                                      if (c == 'v') {
                                        c = str[13];
                                        if (c == 'i') {
                                          c = str[14];
                                          if (c == 's') {
                                            c = str[15];
                                            if (c == 'i') {
                                              c = str[16];
                                              if (c == 'b') {
                                                c = str[17];
                                                if (c == 'l') {
                                                  c = str[18];
                                                  if (c == 'e') {
                                                    c = str[19];
                                                    if (!c) return NEW_SRV_ACTION_USERS_SET_INVISIBLE;
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      } else if (c < 'v') {
                                        if (c == 'c') {
                                          c = str[13];
                                          if (c == 'o') {
                                            c = str[14];
                                            if (c == 'm') {
                                              c = str[15];
                                              if (c == 'p') {
                                                c = str[16];
                                                if (c == 'l') {
                                                  c = str[17];
                                                  if (c == 'e') {
                                                    c = str[18];
                                                    if (c == 't') {
                                                      c = str[19];
                                                      if (c == 'e') {
                                                        c = str[20];
                                                        if (!c) return NEW_SRV_ACTION_USERS_SET_INCOMPLETE;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                      } else {
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  } else if (c < 'i') {
                                    if (c == 'd') {
                                      c = str[11];
                                      if (c == 'i') {
                                        c = str[12];
                                        if (c == 's') {
                                          c = str[13];
                                          if (c == 'q') {
                                            c = str[14];
                                            if (c == 'u') {
                                              c = str[15];
                                              if (c == 'a') {
                                                c = str[16];
                                                if (c == 'l') {
                                                  c = str[17];
                                                  if (c == 'i') {
                                                    c = str[18];
                                                    if (c == 'f') {
                                                      c = str[19];
                                                      if (c == 'i') {
                                                        c = str[20];
                                                        if (c == 'e') {
                                                          c = str[21];
                                                          if (c == 'd') {
                                                            c = str[22];
                                                            if (!c) return NEW_SRV_ACTION_USERS_SET_DISQUALIFIED;
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    } else if (c < 'd') {
                                      if (c == 'b') {
                                        c = str[11];
                                        if (c == 'a') {
                                          c = str[12];
                                          if (c == 'n') {
                                            c = str[13];
                                            if (c == 'n') {
                                              c = str[14];
                                              if (c == 'e') {
                                                c = str[15];
                                                if (c == 'd') {
                                                  c = str[16];
                                                  if (!c) return NEW_SRV_ACTION_USERS_SET_BANNED;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                    } else {
                                    }
                                  } else {
                                    if (c == 'l') {
                                      c = str[11];
                                      if (c == 'o') {
                                        c = str[12];
                                        if (c == 'c') {
                                          c = str[13];
                                          if (c == 'k') {
                                            c = str[14];
                                            if (c == 'e') {
                                              c = str[15];
                                              if (c == 'd') {
                                                c = str[16];
                                                if (!c) return NEW_SRV_ACTION_USERS_SET_LOCKED;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                  }
                                } else {
                                  if (c == 'r') {
                                    c = str[11];
                                    if (c == 'e') {
                                      c = str[12];
                                      if (c == 'j') {
                                        c = str[13];
                                        if (c == 'e') {
                                          c = str[14];
                                          if (c == 'c') {
                                            c = str[15];
                                            if (c == 't') {
                                              c = str[16];
                                              if (c == 'e') {
                                                c = str[17];
                                                if (c == 'd') {
                                                  c = str[18];
                                                  if (!c) return NEW_SRV_ACTION_USERS_SET_REJECTED;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  } else if (c < 'r') {
                                    if (c == 'p') {
                                      c = str[11];
                                      if (c == 'e') {
                                        c = str[12];
                                        if (c == 'n') {
                                          c = str[13];
                                          if (c == 'd') {
                                            c = str[14];
                                            if (c == 'i') {
                                              c = str[15];
                                              if (c == 'n') {
                                                c = str[16];
                                                if (c == 'g') {
                                                  c = str[17];
                                                  if (!c) return NEW_SRV_ACTION_USERS_SET_PENDING;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                  } else {
                                    if (c == 's') {
                                      c = str[11];
                                      if (c == 't') {
                                        c = str[12];
                                        if (c == 'a') {
                                          c = str[13];
                                          if (c == 't') {
                                            c = str[14];
                                            if (c == 'u') {
                                              c = str[15];
                                              if (c == 's') {
                                                c = str[16];
                                                if (!c) return NEW_SRV_ACTION_USERS_SET_STATUS;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                  }
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                      }
                      return 0;
                    }
                    return 0;
                  } else if (c < 's') {
                    if (c == '-') {
                      c = str[5];
                      if (c == 'r') {
                        c = str[6];
                        if (c == 'u') {
                          c = str[7];
                          if (c == 'n') {
                            c = str[8];
                            if (c == '-') {
                              c = str[9];
                              if (c == 'h') {
                                c = str[10];
                                if (c == 'e') {
                                  c = str[11];
                                  if (c == 'a') {
                                    c = str[12];
                                    if (c == 'd') {
                                      c = str[13];
                                      if (c == 'e') {
                                        c = str[14];
                                        if (c == 'r') {
                                          c = str[15];
                                          if (c == 's') {
                                            c = str[16];
                                            if (c == '-') {
                                              c = str[17];
                                              if (c == 'p') {
                                                c = str[18];
                                                if (c == 'a') {
                                                  c = str[19];
                                                  if (c == 'g') {
                                                    c = str[20];
                                                    if (c == 'e') {
                                                      c = str[21];
                                                      if (!c) return NEW_SRV_ACTION_USER_RUN_HEADERS_PAGE;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          } else if (c < 's') {
                                            if (c == '-') {
                                              c = str[16];
                                              if (c == 'd') {
                                                c = str[17];
                                                if (c == 'e') {
                                                  c = str[18];
                                                  if (c == 'l') {
                                                    c = str[19];
                                                    if (c == 'e') {
                                                      c = str[20];
                                                      if (c == 't') {
                                                        c = str[21];
                                                        if (c == 'e') {
                                                          c = str[22];
                                                          if (!c) return NEW_SRV_ACTION_USER_RUN_HEADER_DELETE;
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              } else if (c < 'd') {
                                                if (c == 'c') {
                                                  c = str[17];
                                                  if (c == 'l') {
                                                    c = str[18];
                                                    if (c == 'e') {
                                                      c = str[19];
                                                      if (c == 'a') {
                                                        c = str[20];
                                                        if (c == 'r') {
                                                          c = str[21];
                                                          if (c == '-') {
                                                            c = str[22];
                                                            if (c == 's') {
                                                              c = str[23];
                                                              if (c == 't') {
                                                                c = str[24];
                                                                if (c == 'o') {
                                                                  c = str[25];
                                                                  if (c == 'p') {
                                                                    c = str[26];
                                                                    if (c == '-') {
                                                                      c = str[27];
                                                                      if (c == 't') {
                                                                        c = str[28];
                                                                        if (c == 'i') {
                                                                          c = str[29];
                                                                          if (c == 'm') {
                                                                            c = str[30];
                                                                            if (c == 'e') {
                                                                              c = str[31];
                                                                              if (!c) return NEW_SRV_ACTION_USER_RUN_HEADER_CLEAR_STOP_TIME;
                                                                              return 0;
                                                                            }
                                                                            return 0;
                                                                          }
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  } else if (c < 'l') {
                                                    if (c == 'h') {
                                                      c = str[18];
                                                      if (c == 'a') {
                                                        c = str[19];
                                                        if (c == 'n') {
                                                          c = str[20];
                                                          if (c == 'g') {
                                                            c = str[21];
                                                            if (c == 'e') {
                                                              c = str[22];
                                                              if (c == '-') {
                                                                c = str[23];
                                                                if (c == 'd') {
                                                                  c = str[24];
                                                                  if (c == 'u') {
                                                                    c = str[25];
                                                                    if (c == 'r') {
                                                                      c = str[26];
                                                                      if (c == 'a') {
                                                                        c = str[27];
                                                                        if (c == 't') {
                                                                          c = str[28];
                                                                          if (c == 'i') {
                                                                            c = str[29];
                                                                            if (c == 'o') {
                                                                              c = str[30];
                                                                              if (c == 'n') {
                                                                                c = str[31];
                                                                                if (!c) return NEW_SRV_ACTION_USER_RUN_HEADER_CHANGE_DURATION;
                                                                                return 0;
                                                                              }
                                                                              return 0;
                                                                            }
                                                                            return 0;
                                                                          }
                                                                          return 0;
                                                                        }
                                                                        return 0;
                                                                      }
                                                                      return 0;
                                                                    }
                                                                    return 0;
                                                                  }
                                                                  return 0;
                                                                }
                                                                return 0;
                                                              }
                                                              return 0;
                                                            }
                                                            return 0;
                                                          }
                                                          return 0;
                                                        }
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                  } else {
                                                  }
                                                  return 0;
                                                }
                                              } else {
                                                if (c == 'p') {
                                                  c = str[17];
                                                  if (c == 'a') {
                                                    c = str[18];
                                                    if (c == 'g') {
                                                      c = str[19];
                                                      if (c == 'e') {
                                                        c = str[20];
                                                        if (!c) return NEW_SRV_ACTION_USER_RUN_HEADER_PAGE;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                              }
                                              return 0;
                                            }
                                          } else {
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      } else if (c < 'r') {
                        if (c == 'c') {
                          c = str[6];
                          if (c == 'o') {
                            c = str[7];
                            if (c == 'n') {
                              c = str[8];
                              if (c == 't') {
                                c = str[9];
                                if (c == 'e') {
                                  c = str[10];
                                  if (c == 's') {
                                    c = str[11];
                                    if (c == 't') {
                                      c = str[12];
                                      if (c == 's') {
                                        c = str[13];
                                        if (c == '-') {
                                          c = str[14];
                                          if (c == 'j') {
                                            c = str[15];
                                            if (c == 's') {
                                              c = str[16];
                                              if (c == 'o') {
                                                c = str[17];
                                                if (c == 'n') {
                                                  c = str[18];
                                                  if (!c) return NEW_SRV_ACTION_USER_CONTESTS_JSON;
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 'o') {
                            if (c == 'h') {
                              c = str[7];
                              if (c == 'a') {
                                c = str[8];
                                if (c == 'n') {
                                  c = str[9];
                                  if (c == 'g') {
                                    c = str[10];
                                    if (c == 'e') {
                                      c = str[11];
                                      if (c == '-') {
                                        c = str[12];
                                        if (c == 's') {
                                          c = str[13];
                                          if (c == 't') {
                                            c = str[14];
                                            if (c == 'a') {
                                              c = str[15];
                                              if (c == 't') {
                                                c = str[16];
                                                if (c == 'u') {
                                                  c = str[17];
                                                  if (c == 's') {
                                                    c = str[18];
                                                    if (!c) return NEW_SRV_ACTION_USER_CHANGE_STATUS;
                                                    if (c == '-') {
                                                      c = str[19];
                                                      if (c == '2') {
                                                        c = str[20];
                                                        if (!c) return NEW_SRV_ACTION_USER_CHANGE_STATUS_2;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                          } else {
                          }
                          return 0;
                        }
                      } else {
                      }
                      return 0;
                    }
                  } else {
                  }
                  return 0;
                } else if (c < 'r') {
                  if (c == '-') {
                    c = str[4];
                    if (c == 't') {
                      c = str[5];
                      if (c == 'o') {
                        c = str[6];
                        if (c == 'k') {
                          c = str[7];
                          if (c == 'e') {
                            c = str[8];
                            if (c == 'n') {
                              c = str[9];
                              if (!c) return NEW_SRV_ACTION_USE_TOKEN;
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                } else {
                }
                return 0;
              }
              return 0;
            }
          }
          return 0;
        } else if (c < 'u') {
          if (c == 't') {
            c = str[1];
            if (c == 'o') {
              c = str[2];
              if (c == 'k') {
                c = str[3];
                if (c == 'e') {
                  c = str[4];
                  if (c == 'n') {
                    c = str[5];
                    if (c == 'i') {
                      c = str[6];
                      if (c == 'z') {
                        c = str[7];
                        if (c == 'e') {
                          c = str[8];
                          if (c == '-') {
                            c = str[9];
                            if (c == 'd') {
                              c = str[10];
                              if (c == 'i') {
                                c = str[11];
                                if (c == 's') {
                                  c = str[12];
                                  if (c == 'p') {
                                    c = str[13];
                                    if (c == 'l') {
                                      c = str[14];
                                      if (c == 'a') {
                                        c = str[15];
                                        if (c == 'y') {
                                          c = str[16];
                                          if (c == 'e') {
                                            c = str[17];
                                            if (c == 'd') {
                                              c = str[18];
                                              if (c == '-') {
                                                c = str[19];
                                                if (c == '2') {
                                                  c = str[20];
                                                  if (!c) return NEW_SRV_ACTION_TOKENIZE_DISPLAYED_2;
                                                  return 0;
                                                } else if (c < '2') {
                                                  if (c == '1') {
                                                    c = str[20];
                                                    if (!c) return NEW_SRV_ACTION_TOKENIZE_DISPLAYED_1;
                                                    return 0;
                                                  }
                                                } else {
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              } else if (c < 'k') {
                if (c == 'g') {
                  c = str[3];
                  if (c == 'g') {
                    c = str[4];
                    if (c == 'l') {
                      c = str[5];
                      if (c == 'e') {
                        c = str[6];
                        if (c == '-') {
                          c = str[7];
                          if (c == 'p') {
                            c = str[8];
                            if (c == 'r') {
                              c = str[9];
                              if (c == 'i') {
                                c = str[10];
                                if (c == 'v') {
                                  c = str[11];
                                  if (c == 'i') {
                                    c = str[12];
                                    if (c == 'l') {
                                      c = str[13];
                                      if (c == 'e') {
                                        c = str[14];
                                        if (c == 'g') {
                                          c = str[15];
                                          if (c == 'e') {
                                            c = str[16];
                                            if (c == 'd') {
                                              c = str[17];
                                              if (!c) return NEW_SRV_ACTION_TOGGLE_PRIVILEGED;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          } else if (c < 'p') {
                            if (c == 'i') {
                              c = str[8];
                              if (c == 'n') {
                                c = str[9];
                                if (c == 'c') {
                                  c = str[10];
                                  if (c == 'o') {
                                    c = str[11];
                                    if (c == 'm') {
                                      c = str[12];
                                      if (c == 'p') {
                                        c = str[13];
                                        if (c == 'l') {
                                          c = str[14];
                                          if (c == 'e') {
                                            c = str[15];
                                            if (c == 't') {
                                              c = str[16];
                                              if (c == 'e') {
                                                c = str[17];
                                                if (c == 'n') {
                                                  c = str[18];
                                                  if (c == 'e') {
                                                    c = str[19];
                                                    if (c == 's') {
                                                      c = str[20];
                                                      if (c == 's') {
                                                        c = str[21];
                                                        if (!c) return NEW_SRV_ACTION_TOGGLE_INCOMPLETENESS;
                                                        return 0;
                                                      }
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            } else if (c < 'i') {
                              if (c == 'b') {
                                c = str[8];
                                if (c == 'a') {
                                  c = str[9];
                                  if (c == 'n') {
                                    c = str[10];
                                    if (!c) return NEW_SRV_ACTION_TOGGLE_BAN;
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                            } else {
                              if (c == 'l') {
                                c = str[8];
                                if (c == 'o') {
                                  c = str[9];
                                  if (c == 'c') {
                                    c = str[10];
                                    if (c == 'k') {
                                      c = str[11];
                                      if (!c) return NEW_SRV_ACTION_TOGGLE_LOCK;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                            }
                          } else {
                            if (c == 'v') {
                              c = str[8];
                              if (c == 'i') {
                                c = str[9];
                                if (c == 's') {
                                  c = str[10];
                                  if (c == 'i') {
                                    c = str[11];
                                    if (c == 'b') {
                                      c = str[12];
                                      if (c == 'i') {
                                        c = str[13];
                                        if (c == 'l') {
                                          c = str[14];
                                          if (c == 'i') {
                                            c = str[15];
                                            if (c == 't') {
                                              c = str[16];
                                              if (c == 'y') {
                                                c = str[17];
                                                if (!c) return NEW_SRV_ACTION_TOGGLE_VISIBILITY;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            } else if (c < 'v') {
                              if (c == 'r') {
                                c = str[8];
                                if (c == 'e') {
                                  c = str[9];
                                  if (c == 'g') {
                                    c = str[10];
                                    if (c == '-') {
                                      c = str[11];
                                      if (c == 'r') {
                                        c = str[12];
                                        if (c == 'e') {
                                          c = str[13];
                                          if (c == 'a') {
                                            c = str[14];
                                            if (c == 'd') {
                                              c = str[15];
                                              if (c == 'o') {
                                                c = str[16];
                                                if (c == 'n') {
                                                  c = str[17];
                                                  if (c == 'l') {
                                                    c = str[18];
                                                    if (c == 'y') {
                                                      c = str[19];
                                                      if (!c) return NEW_SRV_ACTION_TOGGLE_REG_READONLY;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                            } else {
                            }
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
              } else {
              }
              return 0;
            } else if (c < 'o') {
              if (c == 'e') {
                c = str[2];
                if (c == 's') {
                  c = str[3];
                  if (c == 't') {
                    c = str[4];
                    if (c == 'i') {
                      c = str[5];
                      if (c == 'n') {
                        c = str[6];
                        if (c == 'g') {
                          c = str[7];
                          if (c == '-') {
                            c = str[8];
                            if (c == 'u') {
                              c = str[9];
                              if (c == 'p') {
                                c = str[10];
                                if (!c) return NEW_SRV_ACTION_TESTING_UP;
                                if (c == '-') {
                                  c = str[11];
                                  if (c == 'a') {
                                    c = str[12];
                                    if (c == 'l') {
                                      c = str[13];
                                      if (c == 'l') {
                                        c = str[14];
                                        if (!c) return NEW_SRV_ACTION_TESTING_UP_ALL;
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            } else if (c < 'u') {
                              if (c == 'd') {
                                c = str[9];
                                if (c == 'o') {
                                  c = str[10];
                                  if (c == 'w') {
                                    c = str[11];
                                    if (c == 'n') {
                                      c = str[12];
                                      if (!c) return NEW_SRV_ACTION_TESTING_DOWN;
                                      if (c == '-') {
                                        c = str[13];
                                        if (c == 'a') {
                                          c = str[14];
                                          if (c == 'l') {
                                            c = str[15];
                                            if (c == 'l') {
                                              c = str[16];
                                              if (!c) return NEW_SRV_ACTION_TESTING_DOWN_ALL;
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                } else if (c < 'o') {
                                  if (c == 'e') {
                                    c = str[10];
                                    if (c == 'l') {
                                      c = str[11];
                                      if (c == 'e') {
                                        c = str[12];
                                        if (c == 't') {
                                          c = str[13];
                                          if (c == 'e') {
                                            c = str[14];
                                            if (!c) return NEW_SRV_ACTION_TESTING_DELETE;
                                            if (c == '-') {
                                              c = str[15];
                                              if (c == 'a') {
                                                c = str[16];
                                                if (c == 'l') {
                                                  c = str[17];
                                                  if (c == 'l') {
                                                    c = str[18];
                                                    if (!c) return NEW_SRV_ACTION_TESTING_DELETE_ALL;
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                } else {
                                }
                                return 0;
                              }
                            } else {
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    } else if (c < 'i') {
                      if (c == '-') {
                        c = str[5];
                        if (c == 's') {
                          c = str[6];
                          if (c == 'u') {
                            c = str[7];
                            if (c == 's') {
                              c = str[8];
                              if (c == 'p') {
                                c = str[9];
                                if (c == 'e') {
                                  c = str[10];
                                  if (c == 'n') {
                                    c = str[11];
                                    if (c == 'd') {
                                      c = str[12];
                                      if (!c) return NEW_SRV_ACTION_TEST_SUSPEND;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        } else if (c < 's') {
                          if (c == 'r') {
                            c = str[6];
                            if (c == 'e') {
                              c = str[7];
                              if (c == 's') {
                                c = str[8];
                                if (c == 'u') {
                                  c = str[9];
                                  if (c == 'm') {
                                    c = str[10];
                                    if (c == 'e') {
                                      c = str[11];
                                      if (!c) return NEW_SRV_ACTION_TEST_RESUME;
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                        } else {
                        }
                        return 0;
                      }
                    } else {
                    }
                    return 0;
                  }
                  return 0;
                } else if (c < 's') {
                  if (c == 'l') {
                    c = str[3];
                    if (c == 'e') {
                      c = str[4];
                      if (c == 'g') {
                        c = str[5];
                        if (c == 'r') {
                          c = str[6];
                          if (c == 'a') {
                            c = str[7];
                            if (c == 'm') {
                              c = str[8];
                              if (c == '-') {
                                c = str[9];
                                if (c == 'r') {
                                  c = str[10];
                                  if (c == 'e') {
                                    c = str[11];
                                    if (c == 'g') {
                                      c = str[12];
                                      if (c == 'i') {
                                        c = str[13];
                                        if (c == 's') {
                                          c = str[14];
                                          if (c == 't') {
                                            c = str[15];
                                            if (c == 'e') {
                                              c = str[16];
                                              if (c == 'r') {
                                                c = str[17];
                                                if (!c) return NEW_SRV_ACTION_TELEGRAM_REGISTER;
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                } else {
                }
                return 0;
              }
            } else {
            }
            return 0;
          }
        } else {
        }
      } else {
        if (c == 'w') {
          c = str[1];
          if (c == 'r') {
            c = str[2];
            if (c == 'i') {
              c = str[3];
              if (c == 't') {
                c = str[4];
                if (c == 'e') {
                  c = str[5];
                  if (c == '-') {
                    c = str[6];
                    if (c == 'x') {
                      c = str[7];
                      if (c == 'm') {
                        c = str[8];
                        if (c == 'l') {
                          c = str[9];
                          if (c == '-') {
                            c = str[10];
                            if (c == 'r') {
                              c = str[11];
                              if (c == 'u') {
                                c = str[12];
                                if (c == 'n') {
                                  c = str[13];
                                  if (c == 's') {
                                    c = str[14];
                                    if (!c) return NEW_SRV_ACTION_WRITE_XML_RUNS;
                                    if (c == '-') {
                                      c = str[15];
                                      if (c == 'w') {
                                        c = str[16];
                                        if (c == 'i') {
                                          c = str[17];
                                          if (c == 't') {
                                            c = str[18];
                                            if (c == 'h') {
                                              c = str[19];
                                              if (c == '-') {
                                                c = str[20];
                                                if (c == 's') {
                                                  c = str[21];
                                                  if (c == 'r') {
                                                    c = str[22];
                                                    if (c == 'c') {
                                                      c = str[23];
                                                      if (!c) return NEW_SRV_ACTION_WRITE_XML_RUNS_WITH_SRC;
                                                      return 0;
                                                    }
                                                    return 0;
                                                  }
                                                  return 0;
                                                }
                                                return 0;
                                              }
                                              return 0;
                                            }
                                            return 0;
                                          }
                                          return 0;
                                        }
                                        return 0;
                                      }
                                      return 0;
                                    }
                                    return 0;
                                  }
                                  return 0;
                                }
                                return 0;
                              }
                              return 0;
                            }
                            return 0;
                          }
                          return 0;
                        }
                        return 0;
                      }
                      return 0;
                    }
                    return 0;
                  }
                  return 0;
                }
                return 0;
              }
              return 0;
            }
            return 0;
          }
          return 0;
        }
      }
    }
  }
  return 0;
}
